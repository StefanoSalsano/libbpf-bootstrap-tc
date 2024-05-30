
#ifndef INFLUXDB_WRAPPER_HPP
#define INFLUXDB_WRAPPER_HPP

#include <sstream>
#include <iostream>
#include <cstdint>
#include <InfluxDBFactory.h>

class InfluxDBWrapper {
public:
	InfluxDBWrapper(const char *uri);
	~InfluxDBWrapper();
	void showDatabases();
	int writeFlowRate(uint64_t ts, uint64_t flowid, uint64_t counter);
private:
	std::unique_ptr<influxdb::InfluxDB> db;
};

#endif
