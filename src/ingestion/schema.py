import polars as pl

PACKET_SCHEMA = pl.Schema({
  "timestamp": pl.Float64,
  "src_ip": pl.Utf8,
  "dst_ip": pl.Utf8,
  "protocol": pl.Int32,
  "length": pl.Int32,
  "time_delta": pl.Float64
})

def validate_dataframe(df: pl.DataFrame) -> pl.DataFrame:
  return df.cast(PACKET_SCHEMA)
