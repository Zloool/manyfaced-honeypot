from datetime import datetime

from infi.clickhouse_orm import models, fields, engines
from infi.clickhouse_orm.database import Database

from manyfaced.common.settings import (CLICKHOUSEIP, CLICKHOUSEPORT,
                             CLICKHOUSEUSER, CLICKHOUSEPASSWORD)


class BearRequests(models.Model):

    EventDate = fields.DateField()
    RequestTime = fields.DateTimeField()
    RequestPath = fields.StringField()
    RequestCommand = fields.StringField()
    RequestVersion = fields.StringField()
    RequestRaw = fields.StringField()
    ProbeName = fields.StringField()
    RequestDetectionID = fields.UInt32Field()
    BotIP = fields.StringField()
    BotCountry = fields.StringField()
    BotUA = fields.StringField()
    BotContinent = fields.StringField()
    BotTracert = fields.StringField()
    BotDNSName = fields.StringField()
    engine = engines.MergeTree('EventDate', ('RequestTime', 'BotIP'))


def Insert(Bear):
    date = datetime.strptime(Bear.timestamp, "%Y-%m-%d %H:%M:%S.%f")
    db = Database('Honeypot', db_url=CLICKHOUSEIP + ':' + CLICKHOUSEPORT,
                  username=CLICKHOUSEUSER, password=CLICKHOUSEPASSWORD)
    DBBear = BearRequests(
        EventDate=date.date(),
        RequestTime=date,
        RequestPath=Bear.path,
        RequestCommand=Bear.command,
        RequestVersion=Bear.version,
        RequestRaw=Bear.raw_request,
        ProbeName=Bear.hostname,
        RequestDetectionID=Bear.isDetected,
        BotIP=Bear.ip,
        BotCountry=Bear.country,
        BotUA=Bear.ua,
        BotContinent=Bear.continent,
        BotTracert=Bear.tracert,
        BotDNSName=Bear.dns_name,
    )
    db.insert({DBBear, })
