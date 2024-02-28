use region;
use region::Allocation;
use std::env;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::LibraryLoader::LoadLibraryA;

use std::fs;

use std::io::prelude::*;
use std::mem;
use std::process;

mod utils;
use crate::utils::*;
mod coff_structs;
use crate::coff_structs::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} /path/to/object/file", args[0]);
        process::exit(1);
    }

    let file_path = &args[1];
    let coff_file = coff_read_file(file_path).unwrap();

    for i in &coff_file {
        print!("{:02X} ", i);
    }
    let header = CoffFileHeader::build(&coff_file);
    println!("{:#x?}", header);

    let mut sections_address: Vec<Allocation> = Vec::new();

    coff_relocate_sections(&coff_file, &header, &mut sections_address);
    let mut coff_text_raw_data = coff_extract_text_section(&coff_file, &header);
    coff_relocate_text_section(&coff_file, &header, &mut coff_text_raw_data);

    coff_execute_entry(&coff_file, &header, &mut coff_text_raw_data);
}

fn coff_relocate_sections(
    coff_file: &Vec<u8>,
    header: &CoffFileHeader,
    sections_address: &mut Vec<Allocation>,
) {
    // let mut
    for i in 0..header.NumberOfSections as usize {
        let section_header = SectionHeader::get(coff_file, &i);
        if section_header.SizeOfRawData == 0 {
            continue;
        }
        let memory = region::alloc(
            section_header.SizeOfRawData as usize,
            region::Protection::READ_WRITE_EXECUTE,
        )
        .unwrap();

        let slice = unsafe {
            std::slice::from_raw_parts_mut(memory.as_ptr::<u8>() as *mut u8, memory.len())
        };
        slice[..section_header.SizeOfRawData as usize].copy_from_slice(
            &coff_file[section_header.PointerToRawData as usize
                ..(section_header.PointerToRawData + section_header.SizeOfRawData) as usize],
        );
        sections_address.push(memory);
        // let tmp = coff_file[section_header.PointerToRawData as usize..];
        // unsafe {
        //     ptr::copy(
        //         tmp.as_ptr(),
        //         sections_address[i].as_mut_ptr(),
        //         section_header.SizeOfRawData as usize,
        //     )
        // }
    }
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
        ..coff_text_section_header.PointerToRawData as usize + data_size
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
    let _coff_header_size: u32 = 20;
    let _coff_section_header_size: u32 = 40;
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
    let _reloc = RelocationTable::build(
        &coff_file[text_section_header.PointerToRelocations as usize..].to_vec(),
    );

    let mut ret = 0;
    for i in 0..text_section_header.NumberOfRelocations as usize {
        let reloc = RelocationTable::get(&coff_file, &text_section_header.PointerToRelocations, &i);
        let pointer = header.PointerToSymbolTable;
        let index = reloc.SymbolTableIndex as usize;
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
    coff_file: &Vec<u8>,
    header: &CoffFileHeader,
    coff_text: &mut Vec<u8>,
) {
    unsafe {
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
            // println!("{:x?}", symbol);

            let is_external: bool =
                symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL as u8 && symbol.SectionNumber == 0;
            let is_internal: bool =
                symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL as u8 && symbol.SectionNumber != 0;

            if is_external {
                let string_table_offset = read32le(&symbol.Name, 4); //utils::vec2u32(&symbol.Name[4..8]);

                let coff_symbol_table_size: usize = 18;
                let _function_full_name = header.PointerToSymbolTable as usize
                    + header.NumberOfSymbols as usize * coff_symbol_table_size
                    + string_table_offset as usize;
                let _func_addr = coff_text_section_header.SizeOfRawData;
                dbg!(string_table_offset, _function_full_name, _func_addr);
                //         // TO DO

                println!("symbol is external,i={i}");
            } else {
                let target_section_index = symbol.SectionNumber - 1;
                println!("Target_Section_Index:{target_section_index}");
                let mut S: *const u8 = coff_file.as_ptr().add(
                    SectionHeader::get(coff_file, &(target_section_index as usize)).PointerToRawData
                        as usize,
                );
                // dbg!(SectionHeader::get(
                //     coff_file,
                //     &(target_section_index as usize)
                // ));
                if is_internal {
                    S = coff_text.as_ptr();
                    println!("symbol is internal,i={i}");
                }

                // dbg!(&reloc, &symbol);
                debug_print_reloc(&reloc);
                debug_print_symbol(&symbol);

                let P = coff_text
                    .as_ptr()
                    .add((reloc.VirtualAddress - coff_text_section_header.VirtualAddress) as usize);

                coff_apply_relocations(coff_text, P, S, &reloc.Type, &symbol.Value);
                // dbg!(P);
            }
        }
    }
}

fn process_external_symbol() {}

fn coff_apply_relocations(
    coff_text: &mut Vec<u8>,
    P: *const u8,
    S: *const u8,
    Type: &u16,
    Value: &u32,
) {
    dbg!(P, S, Type, Value);
    match *Type {
        // Compute the relative address of a symbol from a given section
        //RelativeAddress(Symbol) = AbsoluteAddress(Symbol) - AbsoluteAddress(Section)
        IMAGE_REL_AMD64_REL32 => {
            let v = (unsafe { S.offset_from(P) - 4 + *Value as isize } as u32);
            dbg!(v);

            let P = unsafe { P.offset_from(coff_text.as_ptr()) as usize };
            // println!("Position {:X}", P);
            println!("Before {:X}", read32le(coff_text, P as usize));

            add32(coff_text, P as usize, v);

            println!("After {:X}", read32le(coff_text, P as usize));
        }

        //AbsoluteAddress(Symbol) = AbsoluteAddress(SymbolTable) + Offset(Symbol in SymbolTable)
        IMAGE_REL_AMD64_ADDR32NB => {
            let v = (unsafe { S.offset_from(P) as u32 - 4 });
            dbg!(v);

            // println!("Position {:X}", P);
            println!("Before {:X}", read32le(coff_text, P as usize));

            add32(coff_text, P as usize, v);

            println!("After {:X}", read32le(coff_text, P as usize));
        }
        IMAGE_REL_AMD64_ADDR64 => {
            let v = (unsafe { S.offset_from(P) as u32 });
            dbg!(v);

            // println!("Position {:X}", P);
            println!("Before {:X}", read32le(coff_text, P as usize));

            add32(coff_text, P as usize, v);

            println!("After {:X}", read32le(coff_text, P as usize));
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
        // match String::from_utf8(symbol.Name.clone()) {
        //     Ok(s) => println!("Symbol Name: {}", s),
        //     Err(e) => println!("Error: {:x?}", e),
        // }
        let _text_section_header = coff_get_text_section_header(coff_file, header);
        if symbol.Name == Vec::from("main\0\0\0\0") {
            text_entry = symbol.Value;
            // dbg!(symbol);
            debug_print_symbol(&symbol);
            println!("Try to run:{:04x}", text_entry);
        }
    }

    let exec_text = coff_text;

    println!("{:02X?}", exec_text);
    println!("{:?}", exec_text.len());

    // WinExec("calc",SW_SHOW)
    // let shellcode: Vec<u8> = vec![
    //     0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x33, 0xC0, 0x48, 0x33, 0xDB, 0x48,
    //     0x33, 0xC9, 0x48, 0x33, 0xD2, 0x48, 0x33, 0xFF, 0x48, 0x33, 0xC0, 0x65, 0x48, 0x8B, 0x40,
    //     0x60, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x40, 0x20, 0x48, 0x8B, 0x00, 0x48, 0x8B, 0x00,
    //     0x48, 0x8B, 0x58, 0x20, 0x8B, 0x4B, 0x3C, 0x48, 0x03, 0xCB, 0x8B, 0x89, 0x88, 0x00, 0x00,
    //     0x00, 0x48, 0x03, 0xCB, 0x8B, 0x51, 0x20, 0x48, 0x03, 0xD3, 0x8B, 0x79, 0x24, 0x48, 0x03,
    //     0xFB, 0x8B, 0x49, 0x1C, 0x48, 0x03, 0xCB, 0x48, 0x33, 0xC0, 0x49, 0xB8, 0x57, 0x69, 0x6E,
    //     0x45, 0x78, 0x65, 0x63, 0x00, 0x48, 0x33, 0xF6, 0x8B, 0x34, 0x82, 0x48, 0x03, 0xF3, 0x48,
    //     0x8B, 0x36, 0x4C, 0x3B, 0xC6, 0x74, 0x05, 0x48, 0xFF, 0xC0, 0xEB, 0xEA, 0x4D, 0x33, 0xC0,
    //     0x4D, 0x33, 0xC9, 0x66, 0x44, 0x8B, 0x04, 0x47, 0x46, 0x8B, 0x0C, 0x81, 0x49, 0x03, 0xD9,
    //     0xC6, 0x45, 0xE0, 0x63, 0xC6, 0x45, 0xE1, 0x61, 0xC6, 0x45, 0xE2, 0x6C, 0xC6, 0x45, 0xE3,
    //     0x63, 0xC6, 0x45, 0xE4, 0x00, 0x48, 0xC7, 0xC2, 0x05, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4D,
    //     0xE0, 0xFF, 0xD3, 0x48, 0x8B, 0xE5, 0x5D, 0xC3,
    // ];

    unsafe {
        region::protect(
            exec_text.as_ptr(),
            exec_text.len(),
            region::Protection::READ_WRITE_EXECUTE,
        )
        .expect("GG");
    }

    let shellcode_fn: fn() = unsafe { mem::transmute(exec_text.as_ptr()) };

    unsafe {
        shellcode_fn();
    }
}

fn debug_print_reloc(reloc: &RelocationTable) {
    println!("--------------------------------------------");
    println!("VirtualAddress: {:02X}", reloc.VirtualAddress);
    println!("SymbolTableIndex: {}", reloc.SymbolTableIndex);
    println!("Type: {}", reloc.Type);
    println!("--------------------------------------------");
}

fn debug_print_symbol(symbol: &SymbolTable) {
    println!("--------------------------------------------");
    match String::from_utf8(symbol.Name.clone()) {
        Ok(s) => println!("Symbol Name: {}", s),
        Err(e) => println!("Error: {:x?}", e),
    }
    println!("StorageClass: {}", symbol.StorageClass);
    println!("Value: {}", symbol.Value);
    println!("--------------------------------------------");
}
