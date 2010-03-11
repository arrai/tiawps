#include "sqliteout.h"
#include <stdio.h>
#include <string.h>

#include "tools.h"


void executeSql(sqlite3 *db, const char* cmd)
{
    int rc;
    char *errMsg = 0;
    rc = sqlite3_exec(db, cmd, NULL, 0, &errMsg);
    if( rc!=SQLITE_OK ){
        printf("SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
        exit(1);
    }
}

void initDatabase(const char* filename, sqlite3 **db)
{
    int rc = sqlite3_open(filename, db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(*db));
        sqlite3_close(*db);
        exit(1);
    }
    printf("opened database %s\n",filename);
    executeSql(*db, "create table packets (id integer primary key autoincrement, timestamp datetime, direction integer, opcode integer, data blob);");

    executeSql(*db, "BEGIN;");

    executeSql(*db, "create table header (`key` string primary key, value string);");
}

void freeDatabase(sqlite3 **db)
{
    executeSql(*db, "COMMIT;");

    sqlite3_close(*db);
}

void insertClientBuild(uint8_t *data, uint32_t data_len, sqlite3 *db)
{
    if(data_len <4)
    {
        printf("FATAL: got a packet with opcode = 493 = CMSG_AUTH_SESSION but payload len=%u < 4\n", data_len);
        exit(1);
    }
    uint32_t *clientBuild = (uint32_t*)data;

    const char* insertFormat = "insert into header values ('clientBuild', %u)";
    uint32_t allocSize = strlen(insertFormat)+10 /*uint32*/;
    char* buffer = malloc(allocSize);
    if(!buffer)
    {
        printf("Failed to allocate %u bytes for insert query\n", allocSize);
        exit(1);
    }
    sprintf(buffer, insertFormat, *clientBuild);
    executeSql(db, buffer);
    free(buffer);
}

void insertPacket(uint8_t s2c, uint64_t time, uint16_t opcode, uint8_t *data, uint32_t data_len, void* arg)
{
    sqlite3 *db = (sqlite3*) arg;
    const char* insertFormat = "insert into packets (timestamp, direction, opcode, data) "
        "values (datetime(%u,'unixepoch'), %u, %u, X'%s');";

    uint32_t allocSize = 3/*s2c*/+10 /*time*/+5/*opcode*/+data_len*2+strlen(insertFormat);

    char* queryBuffer = malloc(allocSize);
    if(!queryBuffer)
    {
        printf("Failed to allocate %u bytes for insert query\n", allocSize);
        exit(1);
    }

    sprintf(queryBuffer, insertFormat, (uint32_t)(time/1000000), s2c, opcode, hexEncode(data, data_len));

    executeSql(db, queryBuffer);

    free(queryBuffer);

    if(opcode == 493)
        insertClientBuild(data, data_len, db);
}

