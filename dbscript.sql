CREATE DATABASE Honeypot;
CREATE TABLE Honeypot.bearrequests
(
	EventDate Date,
	RequestTime DateTime,
	RequestPath String,
	RequestCommand String,
	RequestVersion String,
	RequestRaw String,
	ProbeName String,
	RequestDetectionID UInt32,
	BotIP String,
	BotCountry String,
	BotUA String,
	BotContinent String,
	BotTracert String,
	BotDNSName String
)
ENGINE = MergeTree(EventDate, (RequestTime, BotIP), 8192);
