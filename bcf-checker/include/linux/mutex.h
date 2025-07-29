#ifndef _TOOLS_INCLUDE_LINUX_MUTEX_H
#define _TOOLS_INCLUDE_LINUX_MUTEX_H

#include <pthread.h>

struct mutex {
    pthread_mutex_t lock;
};

#define MUTEX_INITIALIZER { .lock = PTHREAD_MUTEX_INITIALIZER }

static inline void mutex_init(struct mutex *m)
{
    pthread_mutex_init(&m->lock, NULL);
}

static inline void mutex_destroy(struct mutex *m)
{
    pthread_mutex_destroy(&m->lock);
}

static inline void mutex_lock(struct mutex *m)
{
    pthread_mutex_lock(&m->lock);
}

static inline int mutex_trylock(struct mutex *m)
{
    return pthread_mutex_trylock(&m->lock) == 0;
}

static inline void mutex_unlock(struct mutex *m)
{
    pthread_mutex_unlock(&m->lock);
}

#endif /* _TOOLS_INCLUDE_LINUX_MUTEX_H */
