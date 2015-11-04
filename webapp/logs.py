import logging
import time

from flask import request, g

from webapp import application

l = logging.getLogger('werkzeug')
l.setLevel(logging.INFO)

SQL_LOG_LEVEL = logging.WARN

application.sqlalchemy_engine_logger = logging.getLogger('sqlalchemy.engine')
application.sqlalchemy_engine_logger.setLevel(SQL_LOG_LEVEL)

application.sqlalchemy_pool_logger = logging.getLogger('sqlalchemy.pool')
application.sqlalchemy_pool_logger.setLevel(SQL_LOG_LEVEL)

application.sqlalchemy_orm_logger = logging.getLogger('sqlalchemy.orm')
application.sqlalchemy_orm_logger.setLevel(SQL_LOG_LEVEL)

application.post_req_logger = logging.getLogger('post_req_logger')
application.pre_req_logger = logging.getLogger('pre_req_logger')
application.pre_req_logger.setLevel(logging.DEBUG)
application.post_req_logger.setLevel(logging.DEBUG)

application.l = logging.getLogger('std_logger')
application.l.setLevel(logging.DEBUG)


class PreReqFilter():

    def filter(self, log_record):
        log_record.url = request.path
        log_record.method = request.method
        log_record.ip = request.environ.get("REMOTE_ADDR")
        log_record.key = request.headers.get('X-Auth-Key', 'none')
        return True


class ResponseFilter():

    def filter(self, log_record):
        log_record.url = request.path
        log_record.method = request.method
        try:
            log_record.code = g.LOG_status_code
        except:
            log_record.code = 1
        try:
            log_record.exec_time = g.LOG_exec_time
        except:
            log_record.exec_time = "err"
        log_record.ip = request.environ.get("REMOTE_ADDR")
        log_record.username = g.get('username', 'guest')
        return True


before_prov = PreReqFilter()
application.pre_req_logger.addFilter(before_prov)

after_prov = ResponseFilter()
application.post_req_logger.addFilter(after_prov)

handler_pre = logging.StreamHandler()
log_format = '{"date":"%(asctime)s","level":"%(levelname)s","api_key":"%(key)s","ip":"%(ip)s","method":"%(method)s","url":"%(url)s","message":"%(message)s"}'

handler_response = logging.StreamHandler()
log_format_response = '{"date":"%(asctime)s","level":"%(levelname)s","username":"%(username)s","ip":"%(ip)s","method":"%(method)s","url":"%(url)s","code":%(code)s,"execTime":"%(exec_time)s","message":"%(message)s"}'

handler_std_log = logging.StreamHandler()
application.l.addHandler(handler_std_log)
l.addHandler(handler_std_log)

handler_sql = logging.StreamHandler()

formatter = logging.Formatter(log_format)
formatter_resp = logging.Formatter(log_format_response)
handler_pre.setFormatter(formatter)
handler_response.setFormatter(formatter_resp)
application.pre_req_logger.addHandler(handler_pre)
application.post_req_logger.addHandler(handler_response)
application.sqlalchemy_engine_logger.addHandler(handler_sql)
application.sqlalchemy_pool_logger.addHandler(handler_sql)
application.sqlalchemy_orm_logger.addHandler(handler_sql)


@application.before_request
def log_entry():
    g.LOG_start_time = time.time()
    application.pre_req_logger.debug("Handling request")


@application.after_request
def log_after(response):
    try:
        g.LOG_status_code = response.status_code
        g.LOG_exec_time = "%.3fms" % float((time.time() - g.LOG_start_time) * 1000)
    except Exception as e:
        application.l.warn("error in after_request handler [%s]" % str(e))
    application.post_req_logger.debug("Handling response")
    return response
