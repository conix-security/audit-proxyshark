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
  {extern void proto_register_dcom_cba (void); proto_register_dcom_cba ();}
  {extern void proto_register_dcom_cba_acco (void); proto_register_dcom_cba_acco ();}
  {extern void proto_register_pn_dcp (void); proto_register_pn_dcp ();}
  {extern void proto_register_pn_io (void); proto_register_pn_io ();}
  {extern void proto_register_pn_mrp (void); proto_register_pn_mrp ();}
  {extern void proto_register_pn_mrrt (void); proto_register_pn_mrrt ();}
  {extern void proto_register_pn_ptcp (void); proto_register_pn_ptcp ();}
  {extern void proto_register_pn_rt (void); proto_register_pn_rt ();}
}

G_MODULE_EXPORT void
plugin_reg_handoff(void)
{
  {extern void proto_reg_handoff_dcom_cba (void); proto_reg_handoff_dcom_cba ();}
  {extern void proto_reg_handoff_dcom_cba_acco (void); proto_reg_handoff_dcom_cba_acco ();}
  {extern void proto_reg_handoff_pn_dcp (void); proto_reg_handoff_pn_dcp ();}
  {extern void proto_reg_handoff_pn_io (void); proto_reg_handoff_pn_io ();}
  {extern void proto_reg_handoff_pn_mrp (void); proto_reg_handoff_pn_mrp ();}
  {extern void proto_reg_handoff_pn_mrrt (void); proto_reg_handoff_pn_mrrt ();}
  {extern void proto_reg_handoff_pn_ptcp (void); proto_reg_handoff_pn_ptcp ();}
  {extern void proto_reg_handoff_pn_rt (void); proto_reg_handoff_pn_rt ();}
}
#endif
