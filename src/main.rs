
use region;
use rust_coffloader::*;
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::mem;
use std::process;
mod utils;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} /path/to/object/file", args[0]);
        process::exit(1);
    }

    let file_path = &args[1];
    let mut coff_file = coff_read_file(file_path).unwrap();

    let header = CoffFileHeader::build(&coff_file);
    println!("{:#x?}", header);


    let mut coff_text_raw_data = coff_extract_text_section(&coff_file, &header);
    coff_relocate_text_section(&mut coff_file, &header, &mut coff_text_raw_data);

    coff_execute_entry(&coff_file, &header, &mut coff_text_raw_data);
}

fn coff_read_file(file_path: &String) -> Result<Vec<u8>, std::io::Error> {
    let mut f = fs::File::open(file_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn coff_extract_text_section(coff_file: &Vec<u8>, header: &CoffFileHeader) -> Vec<u8> {
    let coff_text_section_header = coff_get_text_section_header(&coff_file, &header);
    println!("{:#x?}", coff_text_section_header);
    let data_size = coff_text_section_header.SizeOfRawData as usize
        + coff_get_ext_function_space(&coff_file, &header);
    let mut coff_text_raw_data: Vec<u8> = Vec::new();
    for i in coff_text_section_header.PointerToRawData as usize
        ..coff_text_section_header.PointerToRawData as usize
            + coff_text_section_header.SizeOfRawData as usize
    {
        let b = coff_file.get(i);
        match b {
            Some(b) => coff_text_raw_data.push(*b),
            None => {
                panic!("There is no element in RawData");
            }
        }
    }
    coff_text_raw_data


}

fn coff_get_text_section_header(coff_file: &Vec<u8>, header: &CoffFileHeader) -> SectionHeader {
    let coff_header_size: u32 = 20;
    let coff_section_header_size: u32 = 40;
    for i in 0..(header.NumberOfSections as usize) {

        let section_header = SectionHeader::get(coff_file, &i);

        if section_header.Name == Vec::from(".text\0\0\0") {

            return section_header;
        }
    }
    SectionHeader::empty()
}

fn coff_get_ext_function_space(coff_file: &Vec<u8>, header: &CoffFileHeader) -> usize {
    let text_section_header = coff_get_text_section_header(&coff_file, &header);
    let reloc = RelocationTable::build(
        &coff_file[text_section_header.PointerToRelocations as usize..].to_vec(),
    );

    let mut ret = 0;
    for i in 0..text_section_header.NumberOfRelocations as usize {
        let reloc = RelocationTable::get(&coff_file, &text_section_header.PointerToRelocations, &i);
        let pointer = header.PointerToSymbolTable;
        let index = reloc.SymbolTableIndex as usize + 1;
        let symbol_table = SymbolTable::get(&coff_file, &pointer, &index);
        if symbol_table.StorageClass == IMAGE_SYM_CLASS_EXTERNAL as u8
            && symbol_table.SectionNumber == 0
        {
            ret += 1;
        }
    }
    ret * 8
}

fn coff_relocate_text_section(
    coff_file: &mut Vec<u8>,
    header: &CoffFileHeader,
    coff_text: &mut Vec<u8>,
) {

    let coff_text_section_header = coff_get_text_section_header(&coff_file, &header);
    for i in 0..coff_text_section_header.NumberOfRelocations as usize {
        let reloc = RelocationTable::get(
            coff_file,
            &coff_text_section_header.PointerToRelocations,
            &i,
        );

        let symbol = SymbolTable::get(
            coff_file,
            &header.PointerToSymbolTable,
            &(reloc.SymbolTableIndex as usize),
        );
        println!("{:x?}", symbol);
        let target_section_index = symbol.SectionNumber;
        println!("Target_Section_Index:{target_section_index}");


        let isExternal: bool =
            symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL as u8 && symbol.SectionNumber == 0;
        let isInternal: bool =
            symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL as u8 && symbol.SectionNumber != 0;

        let P = reloc.VirtualAddress - coff_text_section_header.VirtualAddress;

        if isExternal {
            let string_table_offset = utils::read32le(&symbol.Name, 4); //utils::vec2u32(&symbol.Name[4..8]);

            let coff_symbol_table_size: usize = 18;
            let function_full_name = header.PointerToSymbolTable as usize
                + header.NumberOfSymbols as usize * coff_symbol_table_size
                + string_table_offset as usize;
            let func_addr = coff_text_section_header.SizeOfRawData;
            //         // TO DO

            println!("symbol is external,i={i}");
        } else {

            let mut S =
                SectionHeader::get(coff_file, &(target_section_index as usize)).PointerToRawData;
            if isInternal {
                S = 0;
                println!("symbol is internal,i={i}");
            }

            println!("{:x?},{:x?}", P, S);
            coff_apply_relocations(coff_text, P, S, &reloc.Type, &symbol.Value);
        }
    }
}

fn process_external_symbol() {}

fn coff_apply_relocations(coff_text: &mut Vec<u8>, P: u32, S: u32, Type: &u16, Value: &u32) {
    match *Type {
        IMAGE_REL_AMD64_REL32 => {

            utils::add32(coff_text, P as usize, S + Value - P - 4);
            dbg!(P, S, Value, S + Value - P - 4);

        }
        IMAGE_REL_AMD64_ADDR32NB => {
            utils::add32(coff_text, P as usize, S - P - 4);
            dbg!(P, S, S - P - 4);
        }
        IMAGE_REL_AMD64_ADDR64 => {
            utils::add32(coff_text, P as usize, S);
            dbg!(P, S);
        }
        _ => {
            println!("No code to relocate type: {}", Type);
        }
    }
}

fn coff_execute_entry(coff_file: &Vec<u8>, header: &CoffFileHeader, coff_text: &mut Vec<u8>) {

    let mut text_entry = 0;
    for i in 0..header.NumberOfSymbols {
        let symbol = SymbolTable::get(coff_file, &header.PointerToSymbolTable, &(i as usize));
        println!("{:x?}",symbol.Name);
        let text_section_header = coff_get_text_section_header(coff_file, header);
        if symbol.Name == Vec::from("__main\0\0") {

            text_entry = symbol.Value;
            dbg!(symbol);
            println!("Try to run:{:04x}", text_entry);
        }
    }

    //test bytes -> hello world
    const SHELLCODE_BYTES:&[u8]=b"\x48\x8d\x35\x14\x00\x00\x00\x6a\x01\x58\x6a\x0c\x5a\x48\x89\xc7\x0f\x05\x6a\x3c\x58\x31\xff\x0f\x05\xeb\xfe\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a";
    const SHELLCODE_LENGTH: usize = SHELLCODE_BYTES.len();

    let SHELLCODE = coff_text;

    println!("{:02X?}", SHELLCODE);

    unsafe {
        region::protect(
            SHELLCODE.as_ptr(),
            SHELLCODE.len(),
            region::Protection::READ_WRITE_EXECUTE,
        )
        .expect("GG");
    }

    let text_entry = &(SHELLCODE[text_entry as usize]);
    let exec_shellcode: extern "C" fn() -> ! =
        unsafe { mem::transmute(text_entry as *const _ as *const ()) };


    exec_shellcode();
}

