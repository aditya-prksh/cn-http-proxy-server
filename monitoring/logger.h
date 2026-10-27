#ifndef LOGGER_H
#define LOGGER_H
void logger_init(const char *filename);
void logger_log(const char *level,const char *message);
void logger_close(void);
#endif
