/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 */

#ifndef PQCP_HOST_SHIM_PRINTK_H_
#define PQCP_HOST_SHIM_PRINTK_H_

#include <stdio.h>

#define printk(...) printf(__VA_ARGS__)

#endif /* PQCP_HOST_SHIM_PRINTK_H_ */
