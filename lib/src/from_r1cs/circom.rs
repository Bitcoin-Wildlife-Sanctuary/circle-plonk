use crate::field::FM31;
use ark_circom::{CircomCircuit, R1CSFile, R1CS};
use ark_serialize::SerializationError;
use ark_serialize::SerializationError::IoError;
use ark_std::io::{Error, ErrorKind, Read, Seek};
use byteorder::{LittleEndian, ReadBytesExt};

type IoResult<T> = Result<T, SerializationError>;

// This implementation is based on the R1CS reader in `arkworks-rs/circom-compat`,
// originally by Georgios Konstantopoulos.

pub fn witness_read<R: Read + Seek>(mut reader: R) -> IoResult<Vec<FM31>> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != [0x77, 0x74, 0x6e, 0x73] {
        return Err(IoError(Error::new(
            ErrorKind::InvalidData,
            "Invalid magic number",
        )));
    }

    let version = reader.read_u32::<LittleEndian>()?;
    if version != 2 {
        return Err(IoError(Error::new(
            ErrorKind::InvalidData,
            "Unsupported version",
        )));
    }

    let num_sections = reader.read_u32::<LittleEndian>()?;
    if num_sections != 2 {
        return Err(IoError(Error::new(
            ErrorKind::InvalidData,
            "Unsupported number of sections",
        )));
    }

    // Header
    let id_section1 = reader.read_u32::<LittleEndian>()?;
    if id_section1 != 1 {
        return Err(IoError(Error::new(
            ErrorKind::InvalidData,
            "Unexpected ID of the first section",
        )));
    }

    let id_section1_length = reader.read_u64::<LittleEndian>()?;
    if id_section1_length != 12 {
        return Err(IoError(Error::new(
            ErrorKind::InvalidData,
            "Unexpected length of the first section",
        )));
    }

    let n8 = reader.read_u32::<LittleEndian>()?;
    if n8 != 4 {
        return Err(IoError(Error::new(ErrorKind::InvalidData, "Unexpected n8")));
    }

    let fr_q = reader.read_u32::<LittleEndian>()?;
    if fr_q != 2147483647 {
        return Err(IoError(Error::new(
            ErrorKind::InvalidData,
            "Witness is not generated for M31",
        )));
    }

    let num_witnesses = reader.read_u32::<LittleEndian>()?;

    let id_section2 = reader.read_u32::<LittleEndian>()?;
    if id_section2 != 2 {
        return Err(IoError(Error::new(
            ErrorKind::InvalidData,
            "Unexpected ID of the second section",
        )));
    }

    let id_section2_length = reader.read_u64::<LittleEndian>()?;
    if id_section2_length != 4 * num_witnesses as u64 {
        return Err(IoError(Error::new(
            ErrorKind::InvalidData,
            "Unexpected length of the second section",
        )));
    }

    let mut witnesses = vec![];
    for _ in 0..num_witnesses {
        witnesses.push(FM31::from(reader.read_u32::<LittleEndian>()?));
    }
    Ok(witnesses)
}

pub fn load_r1cs_and_witness(
    r1cs_data: impl Read + Seek,
    witness_data: impl Read + Seek,
) -> IoResult<CircomCircuit<FM31>> {
    let mut circuit = load_r1cs_only(r1cs_data)?;
    circuit.witness = Some(witness_read(witness_data)?);
    Ok(circuit)
}

pub fn load_r1cs_only(
    r1cs_data: impl Read + Seek,
) -> IoResult<CircomCircuit<FM31>> {
    let r1cs_file = R1CSFile::<FM31>::new(r1cs_data)?;
    let r1cs: R1CS<FM31> = r1cs_file.into();

    Ok(CircomCircuit::<FM31> {
        r1cs,
        witness: None,
    })
}