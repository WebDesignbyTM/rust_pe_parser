use std::env::args;
use std::path::Path;
use std::fs::File;
use memmap2::Mmap;

const MZPE_MAGIC_SIZE: usize = 2;
const MZPE_MAGIC: [u8; MZPE_MAGIC_SIZE] = [0x4D, 0x5A]; // MZ
const PE_MAGIC: u32 = 0x4550;
const PE_HEADER_POINTER_OFFSET: usize = 0x3C;
const NT_HEADER_SIZE: usize = 0x18; // 24 bytes

struct NtHeader {
    signature: u32,
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32, 
    number_of_symbol_table: u32, 
    size_of_optional_header: u16,
    characteristics: u16
}

impl NtHeader {
    fn from_header_data(data: &[u8]) -> Result<Self, String> {
        let mut navigation_idx: usize = 0;
        if data.len() < navigation_idx + NT_HEADER_SIZE {
            return Err("The mapped file is too short for a NT header.".to_string());
        }

        let signature: u32 = u32::from_le_bytes(data[navigation_idx..navigation_idx + 4].try_into().unwrap());
        if signature != PE_MAGIC {
            return Err(format!("The NT file header doesn't have the correct magic number: 0x{:X} (expected 0x{:X}).", signature, PE_MAGIC));
        }

        navigation_idx += 4;
        let machine: u16 = u16::from_le_bytes(data[navigation_idx..navigation_idx + 2].try_into().unwrap());
        navigation_idx += 2;
        let number_of_sections: u16 = u16::from_le_bytes(data[navigation_idx..navigation_idx + 2].try_into().unwrap());
        navigation_idx += 2;
        let time_date_stamp: u32 = u32::from_le_bytes(data[navigation_idx..navigation_idx + 4].try_into().unwrap());
        navigation_idx += 4;
        let pointer_to_symbol_table: u32 = u32::from_le_bytes(data[navigation_idx..navigation_idx + 4].try_into().unwrap());
        navigation_idx += 4;
        let number_of_symbol_table: u32 = u32::from_le_bytes(data[navigation_idx..navigation_idx + 4].try_into().unwrap());
        navigation_idx += 4;
        let size_of_optional_header: u16 = u16::from_le_bytes(data[navigation_idx..navigation_idx + 2].try_into().unwrap());
        navigation_idx += 2;
        let characteristics: u16 = u16::from_le_bytes(data[navigation_idx..navigation_idx + 2].try_into().unwrap());

        Ok(NtHeader {
            signature,
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbol_table,
            size_of_optional_header,
            characteristics
        })
    }
}

struct PeHeader {
    header_data: Vec<u8>,
    nt_header: NtHeader
}

impl PeHeader {
    fn from_executable_mmap(map: &Mmap) -> Result<Self, String> {
        if map.len() < PE_HEADER_POINTER_OFFSET {
            return Err("The mapped file is too short for a DOS header.".to_string());
        }
        
        // file_header_offset is u32, but usize is necessary to index the byte array
        let file_header_offset: u32 = u32::from_le_bytes(map[PE_HEADER_POINTER_OFFSET..PE_HEADER_POINTER_OFFSET + 4].try_into().unwrap());
        let navigation_idx: usize = usize::try_from(file_header_offset).unwrap();

        // TODO: proper error handling: its up to me to handle this kind of input failure
        let nt_header: NtHeader = NtHeader::from_header_data(&map[navigation_idx..navigation_idx + NT_HEADER_SIZE].to_vec()).unwrap();

        // let header_size: usize = PE_HEADER_POINTER_OFFSET;

        println!("Found the NT header at 0x{:X}", file_header_offset);
        println!("Signature: 0x{:X}", nt_header.signature);
        println!("Machine: 0x{:X}", nt_header.machine);
        println!("Number of sections: 0x{:X}", nt_header.number_of_sections);
        println!("Timedate stamp: 0x{:X}", nt_header.time_date_stamp);
        println!("Pointer to symbol table: 0x{:X}", nt_header.pointer_to_symbol_table);
        println!("Number of symbol table: 0x{:X}", nt_header.number_of_symbol_table);
        println!("Size of optional header: 0x{:X}", nt_header.size_of_optional_header);
        println!("Characteristics 0x{:X}", nt_header.characteristics);

        Ok(PeHeader {
            header_data: inner_header_data.clone(),
            nt_header
        })
    }
}

fn parse_mzpe(fpath: &Path) -> Result<PeHeader, String> {
    match fpath.to_str() {
        None => println!("Invalid file path."),
        Some(fpath_str) => println!("Found {}", fpath_str)
    }

    let executable_file: File = File::open(fpath).unwrap();

    // The Mmap creation is unsafe because of its undefined behaviour,
    // should the file be modified while being operated on
    let mmap: Mmap = unsafe { Mmap::map(&executable_file).unwrap() };

    let file_magic: &[u8] = &mmap[0..MZPE_MAGIC_SIZE];
    if MZPE_MAGIC != file_magic {
        let err_msg: String = format!("Incorrect magic number: {}", String::from_utf8(file_magic.to_vec()).unwrap());
        return Err(err_msg);
    }

    println!("Is the magic number correct? {}", if MZPE_MAGIC == mmap[0..2] {"true"} else {"false"});

    PeHeader::from_executable_mmap(&mmap)
}

fn main() -> Result<(), String> {
    let mut ret_code: Result<(), String> = Ok(());
    let arguments: Vec<String> = args().collect();

    match arguments.len() {
        1 => {
            println!("Please provide an executable file path");
            ret_code = Err(String::from("No file path provided."));
        },
        2 => {
            let fpath = Path::new(&arguments[1]);
            if !fpath.exists() {
                ret_code = Err(String::from("File not found."));
                return ret_code;
            } 
            match parse_mzpe(fpath) {
                Ok(pe_header) => println!("All went well 0x{:X}", pe_header.nt_header.signature),
                Err(e) => ret_code = Err(e)
            }
        },
        _ => {
            println!("Maybe chill with the arguments?");
            ret_code = Err(String::from("Too many arguments."));
        }
    }

    ret_code
}
