#ifndef __LOGGER_H__
#define __LOGGER_H__

#define CONF_LOG(severity, cf, err, fmt, ...) \
    ngx_conf_log_error(severity, cf, err, "%s: " fmt, __FUNCTION__, ##__VA_ARGS__);

#define CONF_LOG_EMERG(cf, err, fmt, ...) \
    CONF_LOG(NGX_LOG_EMERG, cf, err, fmt, ##__VA_ARGS__);

#define LOG(severity, log, err, fmt, ...) \
    ngx_log_error(severity, log, err, "%s: " fmt, __FUNCTION__, ##__VA_ARGS__);

#define LOG_EMERG(log, err, fmt, ...) \
    LOG(NGX_LOG_EMERG, log, err, fmt, ##__VA_ARGS__);

#define LOG_ERR(log, err, fmt, ...) \
    LOG(NGX_LOG_ERR, log, err, fmt, ##__VA_ARGS__);

#define LOG_INFO(log, fmt, ...) \
    LOG(NGX_LOG_INFO, log, 0, fmt, ##__VA_ARGS__);

#define LOG_DEBUG(log, fmt, ...) \
    LOG(NGX_LOG_DEBUG, log, 0, fmt, ##__VA_ARGS__);

#endif // __LOGGER_H__
