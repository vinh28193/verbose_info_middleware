import logging
import os
import time
import psutil

from django.conf import settings
from django.db import connections
from django.urls import resolve
from django.utils.timezone import now
from django.utils.deprecation import MiddlewareMixin
from django.middleware.locale import LocaleMiddleware as DjLocaleMiddleware
from .compat import json
from .logstash import capture_manually
from .mongo_client import log_mongo, MongoTable
from omisocial.apps.notification.notification_provider import push_telegram

logger = logging.getLogger(__name__)


def get_report_time(fm="%A, %d. %B %Y %I:%M%p (%Z)"):
    return now().strftime(fm)


def telegram_waring(content):
    push_telegram(content=content)


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        _ip = x_forwarded_for.split(',')[0]
    else:
        _ip = request.META.get('REMOTE_ADDR')
    return _ip


def clean_text(text):
    if isinstance(text, bytes):
        # noinspection PyBroadException
        try:
            return text.decode('utf-8') \
                .replace('\\n', '') \
                .replace('\\t', '') \
                .replace('\\r', '')
        except Exception:
            pass
    return str(text)


MAX_QUERY_COUNT = 50
MAX_QUERY_EXECUTED_TIME = 1

ROUTE_EXCLUDES = [
    'POST api/v1/orders/checkout/<str:token>/',
    'POST api/v1/orders/products/',
    'POST api/v1/products/',
    'PATCH api/v1/products/<int:pk>/',
    'PUT api/v1/products/<int:pk>/',
    'POST api/v1/products/<int:pk>/variants/',
    'PATCH api/v1/products/<int:pk>/variants/<int:variant_id>/',
    'PUT api/v1/products/<int:pk>/variants/<int:variant_id>/',
    'POST api/v1/landings/',
]


class LocaleMiddleware(DjLocaleMiddleware):
    pass


def waring_too_many_query_executed(path, method, count, executed_time):
    content = f"<b>Too many query executed when {method} {path}</b>"
    content += "\n"
    content += f"<b>Count</b>: {count}"
    content += "\n"
    content += f"<b>Executed</b>: {executed_time}s"
    content += "\n"
    content += f"<b>Reported at</b>: {get_report_time()}"
    telegram_waring(content)


def waring_too_slow_query_executed(path, method, query):
    content = f"<b>Too slow query executed when {method} {path}</b>"
    content += "\n"
    content += f"<b>Query</b>: <code>{query['sql']}</code>"
    content += "\n"
    content += f"<b>Time</b>: {query['time']}s"
    content += "\n"
    content += f"<b>Reported at</b>: {get_report_time()}"
    telegram_waring(content)


class VerboseInfoMiddleware(MiddlewareMixin):

    def process_request(self, request):
        mem_before = psutil.Process(os.getpid()).memory_info()
        start = time.time()
        query_params = request.GET
        # Get request data
        request_data = request.body
        # noinspection PyBroadException
        try:
            request_data = json.loads(request.body)
        except Exception:
            # noinspection PyBroadException
            try:
                request_data = clean_text(request.body)
            except Exception:
                pass

        response = self.get_response(request)
        path = request.path
        method = request.method.upper()
        user = None
        if getattr(request, 'user', None) is not None:
            user = request.user

        capture_manually(
            method=method, url=request.get_raw_uri(),
            status_code=response.status_code,
            response_time=round(time.time() - start, 6),
            user_id=user.id if user and not user.is_anonymous else 0
        )
        mem_after = psutil.Process(os.getpid()).memory_info()
        queries_count = 0
        queries = []
        for conn in connections.all():
            queries_count += len(conn.queries)
            queries.extend(conn.queries)
        sql_exec_time = round(sum([
            float(q["time"]) for q in queries
        ]), 6)
        try:
            max_sql_exec_time = max([
                float(q["time"]) for q in queries
            ])
        except ValueError:
            max_sql_exec_time = 0

        if settings.DEBUG:
            logger.debug("==== Verbose info ====")
            if user:
                logger.debug(f"| Authorized: {user}")
            logger.debug(f"| Endpoint: {path}")
            logger.debug(f"| Method: {method}")
            logger.debug(f"| Execution time: {round(time.time() - start, 6)}s")
            logger.debug(f"| Queries count: {queries_count}")
            logger.debug(f"| SQL execution time: {sql_exec_time}s")
            logger.debug(f"| Slowest SQL execution time: {max_sql_exec_time}s")
            if queries_count > 0:
                logger.debug(
                    f"| Average SQL execution time:"
                    f" {round(sql_exec_time / queries_count, 6)}s"
                )
            logger.debug(
                f"| Memory used:"
                f" {round((mem_after.rss - mem_before.rss) / 1024):,} Kb"
            )
            logger.debug("======================")
            if settings.PRINT_SQL:
                for conn in connections.all():
                    for idx, q in enumerate(conn.queries):
                        logger.debug(f"{idx + 1}: {q}")
        resolve_path = resolve(request.path)
        route = resolve_path.route
        route = f"{method} {route}"

        if route not in ROUTE_EXCLUDES:
            if queries_count > MAX_QUERY_COUNT:
                waring_too_many_query_executed(
                    path=path, method=method.upper(), count=queries_count,
                    executed_time=sql_exec_time
                )
            for query in list(filter(
                lambda x: float(x["time"]) >= MAX_QUERY_EXECUTED_TIME, queries
            )):
                waring_too_slow_query_executed(
                    path=path, method=method.upper(), query=query
                )

        if settings.REQUEST_LOG_ENABLE and route in settings.REQUEST_LOG_ROUTES:

            response_content = None
            # noinspection PyBroadException
            try:
                response_content = json.loads(response.getvalue())
            except Exception:
                # noinspection PyBroadException
                try:
                    response_content = clean_text(response.getvalue().decode())
                except Exception:
                    pass

            auth_by = None
            log = {
                "host": request.get_host(),
                "uri": request.build_absolute_uri(),
                "path": path,
                "method": method,
                "ip": get_client_ip(request),
                "request_headers": eval(str(request.headers)),
                "request_data": request_data,
                "query_params": query_params,
                "user_id": request.user.id,
                "customer_id": None,
                "landing_id": None,
                "app_id": None,
                "auth_by": auth_by,
                "is_authenticated": request.user.is_authenticated,
                "queries_count": queries_count,
                "queries_exec_time": sql_exec_time,
                "queries_slowest_exec_time": max_sql_exec_time,
                "response_status": response.status_code,
                "response_content": response_content,
                "memory_used": round((mem_after.rss - mem_before.rss) / 1024),
                "exe_time": round(time.time() - start, 6),

            }
            log_mongo(log, MongoTable.LOG_REQUEST)

        return response
