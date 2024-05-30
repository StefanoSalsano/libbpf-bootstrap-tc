
#include "influxdb_wrapper.hpp"

InfluxDBWrapper::InfluxDBWrapper(const char *uri) {
	std::string cppString = uri;

	/* throws an exception if we cannot connect to influxdb and/or
	 * create the db.
	 */
	db = influxdb::InfluxDBFactory::Get(cppString);
	db->createDatabaseIfNotExists();
}

InfluxDBWrapper::~InfluxDBWrapper() {
	db.reset();
}

void InfluxDBWrapper::showDatabases() {
	try {
		for (auto i: db->query("SHOW DATABASES"))
			std::cout << i.getTags() <<std::endl;
	} catch (...) { /* do nothing */ }
}

int InfluxDBWrapper::writeFlowRate(uint64_t ts,
		uint64_t flowid, uint64_t counter) {
	influxdb::Point point("rate");
	double ccnt = 1.0D * counter;
	std::string flowid_str;
	std::ostringstream oss;

	oss << flowid;
	flowid_str = oss.str();
	point.addTag("flowid", flowid_str);

	point.addField("value", ccnt);

	//FIXME: use ts instead of now()
	point.setTimestamp(std::chrono::system_clock::now());

	try {
		db->write(std::move(point));
		return 0;
	} catch (...) { /* do nothing */ }

	return -EINVAL;
}
