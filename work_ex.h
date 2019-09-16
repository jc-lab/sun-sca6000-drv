#ifndef __WORK_EX_H__
#define __WORK_EX_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <linux/workqueue.h>

typedef int (*work_ex_cb_t)(void *arg);

typedef struct work_ex_struct {
	struct work_struct work;
	work_ex_cb_t cb;
} work_ex_t;

#ifdef __cplusplus
}
#endif

#endif /* __WORK_EX_H__ */
