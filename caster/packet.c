#include "conf.h"
#include "caster.h"
#include "packet.h"

struct packet *packet_new(size_t len_raw, struct caster_state *caster) {
	struct packet *this = (struct packet *)malloc(sizeof(struct packet) + len_raw);
	P_MUTEX_INIT(&this->mutex, NULL);
	this->datalen = len_raw;
	this->refcnt = 1;
	this->caster = caster;
	return this;
}

/*
 * Packet freeing function with a reference count
 * for zero copy mode.
 */
void packet_free(struct packet *packet) {
	/*
	 * When not in zero-copy mode, don't lock the packet as
	 * we are the only thread handling it.
	 */
	if (!packet->caster->config->zero_copy) {
		free((void *)packet);
		return;
	}

	P_MUTEX_LOCK(&packet->mutex);
	packet->refcnt--;
	if (packet->refcnt == 0) {
		P_MUTEX_DESTROY(&packet->mutex);
		free((void *)packet);
	} else {
		P_MUTEX_UNLOCK(&packet->mutex);
	}
}
