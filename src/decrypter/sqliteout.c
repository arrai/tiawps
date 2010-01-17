#include "sqliteout.h"
#include <stdio.h>
#include <string.h>

#include "tools.h"


void initDatabase(const char* filename, sqlite3 **db)
{
    int rc = sqlite3_open(filename, db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(*db));
        sqlite3_close(*db);
        exit(1);
    }
    printf("opened database %s\n",filename);
    char *errMsg = 0;
    rc = sqlite3_exec(*db, "create table packets (id integer primary key autoincrement, timestamp datetime, direction integer, opcode integer, data blob);", NULL, 0, &errMsg);

    if( rc!=SQLITE_OK ){
        printf("SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
        exit(1);
    }
    rc = sqlite3_exec(*db, "BEGIN;", NULL, 0, &errMsg);

    if( rc!=SQLITE_OK ){
        printf("SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
        exit(1);
    }

}

void freeDatabase(sqlite3 **db)
{
    char *errMsg = 0;
    int rc = sqlite3_exec(*db, "COMMIT;", NULL, 0, &errMsg);

    if( rc!=SQLITE_OK ){
        printf("SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
        exit(1);
    }
    sqlite3_close(*db);
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

    char *errMsg = 0;
    int rc = sqlite3_exec(db, queryBuffer, NULL, 0, &errMsg);

    free(queryBuffer);
    if( rc!=SQLITE_OK ){
        printf("SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
        exit(1);
    }

}
