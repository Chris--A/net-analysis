use super::BtError;

pub fn err<T>() -> Result<T, BtError> {
    Err(BtError::Unsupported("Linux support (BlueZ) arrives in milestone M6".into()))
}
