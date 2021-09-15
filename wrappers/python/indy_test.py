import asyncio
import indy
import json
import time

PERF_ROWS = 10000


async def perf_test():
    wname = "test_wallet"
    key = "9943kWm1GSQjzSpYADY2HsUWR8Bgc428bNAEP79jgb2e"
    wallet_config = {"id": wname, "storage_type": None}
    wallet_creds = {"key": key, "key_derivation_method": "RAW"}

    if False:
        from ctypes import cdll

        stg_lib = cdll.LoadLibrary("libindystrgpostgres.dylib")
        assert stg_lib.postgresstorage_init() == 0
        wallet_config["storage_type"] = "postgres_storage"
        wallet_config["storage_config"] = {
            # "url": "172.17.0.1:5432",
            "url": "localhost:5432",
            "tls": "None",
            "max_connections": 10,
            "min_idle_time": 0,
            "connection_timeout": 10,
        }
        wallet_creds["storage_credentials"] = {
            "account": "postgres",
            "password": "pgpass",
            "admin_account": "postgres",
            "admin_password": "pgpass",
        }

    config = json.dumps(wallet_config)
    creds = json.dumps(wallet_creds)

    try:
        await indy.wallet.delete_wallet(config, creds)
    except indy.IndyError as err:
        if err.error_code != indy.error.ErrorCode.WalletNotFoundError:
            raise

    await indy.wallet.create_wallet(config, creds)
    handle = await indy.wallet.open_wallet(config, creds)

    insert_start = time.perf_counter()
    for idx in range(PERF_ROWS):
        tags_json = json.dumps({"~plaintag": "a", "enctag": "b"})
        await indy.non_secrets.add_wallet_record(
            handle, "category", f"name-{idx}", "value", tags_json
        )
    dur = time.perf_counter() - insert_start
    print(f"insert duration ({PERF_ROWS} rows): {dur:0.2f}s")

    rc = 0
    tags = 0
    options_json = json.dumps(
        {
            "retrieveType": True,
            "retrieveValue": True,
            "retrieveTags": True,
        }
    )
    fetch_start = time.perf_counter()
    for idx in range(PERF_ROWS):
        result_json = await indy.non_secrets.get_wallet_record(
            handle, "category", f"name-{idx}", options_json
        )
        result = json.loads(result_json)
        rc += 1
        tags += len(result["tags"])
    dur = time.perf_counter() - fetch_start
    print(f"fetch duration ({rc} rows, {tags} tags): {dur:0.2f}s")

    rc = 0
    tags = 0
    options_json = json.dumps(
        {
            "retrieveRecords": True,
            "retrieveTotalCount": False,
            "retrieveType": True,
            "retrieveValue": True,
            "retrieveTags": True,
        }
    )
    scan_start = time.perf_counter()
    search_handle = await indy.non_secrets.open_wallet_search(
        handle, "category", "{}", options_json
    )
    while True:
        result_json = await indy.non_secrets.fetch_wallet_search_next_records(
            handle, search_handle, 20
        )
        results = json.loads(result_json)
        if results["records"]:
            for row in results["records"]:
                rc += 1
                tags += len(row["tags"])
        else:
            break
    dur = time.perf_counter() - scan_start
    print(f"scan duration ({rc} rows, {tags} tags): {dur:0.2f}s")


if __name__ == "__main__":

    asyncio.get_event_loop().run_until_complete(perf_test())

    print("done")
