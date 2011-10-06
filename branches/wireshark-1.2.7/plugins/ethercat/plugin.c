/* Do not modify this file.  */
/* It is created automatically by the Makefile.  */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gmodule.h>

#include "moduleinfo.h"

#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = VERSION;

/* Start the functions we need for the plugin stuff */

G_MODULE_EXPORT void
plugin_register (void)
{
  {extern void proto_register_ams (void); proto_register_ams ();}
  {extern void proto_register_ecat (void); proto_register_ecat ();}
  {extern void proto_register_ecat_mailbox (void); proto_register_ecat_mailbox ();}
  {extern void proto_register_ethercat_frame (void); proto_register_ethercat_frame ();}
  {extern void proto_register_ioraw (void); proto_register_ioraw ();}
  {extern void proto_register_nv (void); proto_register_nv ();}
}

G_MODULE_EXPORT void
plugin_reg_handoff(void)
{
  {extern void proto_reg_handoff_ams (void); proto_reg_handoff_ams ();}
  {extern void proto_reg_handoff_ecat (void); proto_reg_handoff_ecat ();}
  {extern void proto_reg_handoff_ecat_mailbox (void); proto_reg_handoff_ecat_mailbox ();}
  {extern void proto_reg_handoff_ethercat_frame (void); proto_reg_handoff_ethercat_frame ();}
  {extern void proto_reg_handoff_ioraw (void); proto_reg_handoff_ioraw ();}
  {extern void proto_reg_handoff_nv (void); proto_reg_handoff_nv ();}
}
#endif
