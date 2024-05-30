
#include "influxdb_wrapper.hpp"
#include "influxdb_wrapper_int.h"

/* declared in magic_interface.h but defined here */
struct MHandler {
	void *obj;
};

MHandler_t *create_influxdb(const char *uri)
{
	InfluxDBWrapper *obj;
	MHandler_t *h;

	h = (typeof(h))malloc(sizeof(*h));
	if (!h)
		return NULL;

	try {
		obj = new InfluxDBWrapper(uri);
	} catch(...) {
		/* an exception occurred during wrapper creation */
		free(h);
		return NULL;
	}

	h->obj = obj;
	return h;
}

void show_databases_influxdb(MHandler_t *h)
{
	InfluxDBWrapper *obj;

	obj = static_cast<InfluxDBWrapper *>(h->obj);
	obj->showDatabases();
}

void destroy_influxdb(MHandler_t *h)
{
	InfluxDBWrapper *obj;

	obj = static_cast<InfluxDBWrapper *>(h->obj);
	/* Delete the obj instance */
	delete obj;

	/* destroy the opaque handler */
	free(h);
}

int write_flowrate_influxdb(MHandler_t *h,
			    uint64_t ts, uint64_t flowid, uint64_t counter)
{
	InfluxDBWrapper *obj;

	obj = static_cast<InfluxDBWrapper *>(h->obj);
	return obj->writeFlowRate(ts, flowid, counter);
}
