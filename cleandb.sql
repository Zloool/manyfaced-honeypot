DROP TABLE tableTemp;
CREATE TABLE tableTemp
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
INSERT INTO tableTemp SELECT * from bearrequests;
DROP TABLE bearrequests;
CREATE TABLE bearrequests
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
INSERT INTO bearrequests SELECT * from tableTemp where substring(BotIP,1,5)!='37.55' and (BotIP!='127.0.0.1') and (BotIP!='93.75.197.72');
