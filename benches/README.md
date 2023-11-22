### Aries Askar Benchmarks

Running `cargo bench` will run the benchmarks against an in-memory SQLite by default.

To run against a Postgres, you need to set the `POSTGRES_URL` environment variable like so:
```sh
docker run --rm -p 5432:5432 --net aries --name aries-test-postgres -e POSTGRES_PASSWORD=mysecretpassword -d postgres
POSTGRES_URL=postgres://postgres:mysecretpassword@localhost:5432/test-db cargo bench
```

To run comparison benchmarks:
```sh
git checkout main
cargo bench -- --save-baseline main
git checkout feature
cargo bench -- --save-baseline feature

# Compare `feature` (new) to `main` (original)
cargo bench -- --load-baseline feature --baseline main
```
