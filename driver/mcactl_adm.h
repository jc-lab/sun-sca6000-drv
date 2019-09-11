/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2006 Sun Microsystems, Inc. All Rights Reserved.
 *
 *     Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistribution of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * - Redistribution in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *     Neither the name of Sun Microsystems, Inc. or the names of contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *     This software is provided "AS IS," without a warranty of any kind. ALL
 * EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES, INCLUDING
 * ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * OR NON-INFRINGEMENT, ARE HEREBY EXCLUDED. SUN MICROSYSTEMS, INC. ("SUN")
 * AND ITS LICENSORS SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE
 * AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS
 * DERIVATIVES. IN NO EVENT WILL SUN OR ITS LICENSORS BE LIABLE FOR ANY LOST
 * REVENUE, PROFIT OR DATA, OR FOR DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL,
 * INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER CAUSED AND REGARDLESS OF THE THEORY
 * OF LIABILITY, ARISING OUT OF THE USE OF OR INABILITY TO USE THIS SOFTWARE,
 * EVEN IF SUN HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 *     You acknowledge that this software is not designed, licensed or
 * intended for use in the design, construction, operation or maintenance of
 * any nuclear facility.
 */

#ifndef	_SYS_MCACTL_ADM_H
#define	_SYS_MCACTL_ADM_H

#pragma ident	"@(#)mcactl_adm.h	1.3	06/12/20 SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	MCASECCMD_HANDSHAKE	0x00000001	/* Handshake message */
#define	MCASECCMD_RESET		0x00000002	/* Will reset firmware */
#define	MCASECCMD_ZEROIZE	0x00000004	/* Will zeroize firmware */
#define	MCASECCMD_KSUPDATE	0x00000008	/* Will update keystore */
#define	MCASECCMD_OWNED		0x00000010	/* Board is initialized */
#define	MCASECCMD_DISCONNECT	0x00000020	/* FW performed auto-logout */
#define	MCASECCMD_RESTORE	0x00000040	/* Restoring master key */
#define	MCASECCMD_FAILSAFE	0x00000080	/* Board is in failsafe mode */
#define	MCASECCMD_INITIALIZE	0x00000100	/* Will initialize card */
#define	MCASECCMD_FIPS		0x00000200	/* Card is in FIPS mode */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MCACTL_ADM_H */
