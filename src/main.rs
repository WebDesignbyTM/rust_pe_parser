use std::env::args;
use std::path::Path;
use std::fs::File;
use memmap2::Mmap;

const MZPE_MAGIC_SIZE: usize = 2;
const MZPE_MAGIC: [u8; MZPE_MAGIC_SIZE] = [0x4D, 0x5A]; // MZ
// const PE_MAGIC_SIZE: usize = 4;
// const PE_MAGIC: [u8; PE_MAGIC_SIZE] = [0x50, 0x45, 0x0 ,0x0]; // PE\0\0
const PE_MAGIC: u32 = 0x50450000; // PE\0\0
const PE_HEADER_POINTER_OFFSET: usize = 0x3C;
const PE_FILE_HEADER_SIZE: usize = 0x18; // 24 bytes

struct PeHeader {
    header_data: Vec<u8>,
    signature: u32,
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32, 
    number_of_symbol_table: u32, 
    size_of_optional_header: u16,
    characteristics: u16
}

impl PeHeader {
    fn from_executable_mmap(map: &Mmap) -> Result<Self, String> {
        if map.len() < PE_HEADER_POINTER_OFFSET {
            return Err("The mapped file is too short for a DOS header.".to_string());
        }
        
        // file_header_offset is u32, but usize is necessary to index the byte array
        let file_header_offset: u32 = u32::from_le_bytes(map[PE_HEADER_POINTER_OFFSET..PE_HEADER_POINTER_OFFSET + 4].try_into().unwrap());
        let mut navigation_idx: usize = usize::try_from(file_header_offset).unwrap();

        if map.len() < navigation_idx + PE_FILE_HEADER_SIZE {
            return Err("The mapped file is too short for a NT header.".to_string());
        }

        let signature: u32 = u32::from_le_bytes(map[navigation_idx..navigation_idx + 4].try_into().unwrap());
        navigation_idx += 4;
        let machine: u16 = u16::from_le_bytes(map[navigation_idx..navigation_idx + 2].try_into().unwrap());
        navigation_idx += 2;
        let number_of_sections: u16 = u16::from_le_bytes(map[navigation_idx..navigation_idx + 2].try_into().unwrap());
        navigation_idx += 2;
        let time_date_stamp: u32 = u32::from_le_bytes(map[navigation_idx..navigation_idx + 4].try_into().unwrap()); // something goes wrong here
        navigation_idx += 4;
        let pointer_to_symbol_table: u32 = u32::from_le_bytes(map[navigation_idx..navigation_idx + 4].try_into().unwrap());
        navigation_idx += 4;
        let number_of_symbol_table: u32 = u32::from_le_bytes(map[navigation_idx..navigation_idx + 4].try_into().unwrap());
        navigation_idx += 4;
        let size_of_optional_header: u16 = u16::from_le_bytes(map[navigation_idx..navigation_idx + 2].try_into().unwrap());
        navigation_idx += 2;
        let characteristics: u16 = u16::from_le_bytes(map[navigation_idx..navigation_idx + 2].try_into().unwrap());
        navigation_idx += 2;


        // let header_size: usize = PE_HEADER_POINTER_OFFSET;

        println!("Found the NT header at 0x{:x}", file_header_offset);
        println!("Signature: 0x{:x}", signature);
        println!("Machine: 0x{:x}", machine);
        println!("Number of sections: 0x{:x}", number_of_sections);
        println!("Timedate stamp: 0x{:x}", time_date_stamp);
        println!("Pointer to symbol table: 0x{:x}", pointer_to_symbol_table);
        println!("Number of symbol table: 0x{:x}", number_of_symbol_table);
        println!("Size of optional header: 0x{:x}", size_of_optional_header);
        println!("Characteristics 0x{:x}", characteristics);

        Ok(PeHeader {
            header_data: map[0..navigation_idx].to_vec(),
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

fn parse_mzpe(fpath: &Path) -> Result<(), String> {
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

    PeHeader::from_executable_mmap(&mmap);
    Ok(())
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
                Ok(()) => println!("All went well"),
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
