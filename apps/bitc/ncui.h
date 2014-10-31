#ifndef __NCUI_H__
#define __NCUI_H__

int  ncui_init(void);
void ncui_exit(void);

void ncui_input_cb(void *clientData);
void ncui_time_cb(void *clientData);
void ncui_log_cb(const char *ts, const char *str, void *clientData);

void ncui_info_update(void);
void ncui_status_update(bool update);
void ncui_wallet_update(void);
void ncui_peers_update(void);
void ncui_tx_update(void);
void ncui_fx_update(void);

#endif /* __NCUI_H__ */
