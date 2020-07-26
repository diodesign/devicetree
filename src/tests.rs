/* Device tree blob parsing and writing
 *
 * Unit tests
 * 
 * TODO: Generate DTBs on the fly from qemu and parse them
 * 
 * (c) Chris Williams, 2020.
 *
 * See LICENSE for usage and copying.
 */

use std::path::Path;
use std::fs::read;
use super::{DeviceTree, DeviceTreeBlob};

struct DeviceTrees
{
    pub rv32: DeviceTree,
    pub rv64: DeviceTree
}

impl DeviceTrees
{
    pub fn new() -> DeviceTrees
    {
        let rv32_path = Path::new("samples/qemu-rv32-virt-smp2-m128.dtb");
        let rv32_bytes = match read(&rv32_path)
        {
            Ok(bytes) => bytes,
            Err(error_type) => panic!("Couldn't read contents of {}: {:?}", rv32_path.display(), error_type)
        };

        let rv64_path = Path::new("samples/qemu-rv64-virt-smp2-m128.dtb");
        let rv64_bytes = match read(&rv64_path)
        {
            Ok(bytes) => bytes,
            Err(error_type) => panic!("Couldn't read contents of {}: {:?}", rv64_path.display(), error_type)
        };

        DeviceTrees
        {
            rv32: match DeviceTreeBlob::from_slice(rv32_bytes.as_slice())
            {
                Ok(blob) => match blob.to_parsed()
                {
                    Ok(dt) => dt,
                    Err(error_type) => panic!("Couldn't parse RV32 device tree: {:?}", error_type)
                },
                Err(error_type) => panic!("Couldn't create RV32 blob from slice: {:?}", error_type)
            },

            rv64: match DeviceTreeBlob::from_slice(rv64_bytes.as_slice())
            {
                Ok(blob) => match blob.to_parsed()
                {
                    Ok(dt) => dt,
                    Err(error_type) => panic!("Couldn't parse RV64 device tree: {:?}", error_type)
                },
                Err(error_type) => panic!("Couldn't create RV64 blob from slice: {:?}", error_type)
            }
        }
    }
}

/* return the number of CPU cores in the system */
fn count_cpu_cores(tree: &DeviceTree) -> usize
{
    let cells = tree.get_address_size_cells(&format!("/cpus"));
    let mut count = 0;
    for node in tree.iter(&format!("/cpus/cpu"), 2)
    {
        let cpu_ids = match tree.get_property(&node, &format!("reg"))
        {
            Ok(prop) => match prop.as_multi_u32()
            {
                Ok(value) => value,
                Err(error_type) => panic!("Couldn't read CPU ID: {:?}", error_type)
            },
            Err(error_type) => panic!("Couldn't read CPU property: {:?}", error_type)
        };

        count = count + (cpu_ids.len() / cells.address);
    }

    count
}

/* return the total RAM capacity in the system in bytes */
fn count_ram(tree: &DeviceTree) -> usize
{
    let mut total = 0;

    /* get the width of each memory area's base address and size from the parent node */
    let cells = tree.get_address_size_cells(&format!("/"));

    /* iterate over all RAM banks in the system */
    for mem in tree.iter(&format!("/memory@"), 1)
    {
        /* the base address and size are stored consecutively in the reg list */
        let reg = match tree.get_property(&mem, &format!("reg"))
        {
            Ok(r) => r,
            Err(e) => panic!("Failed to read memory bank information. Reason: {:?}", e)
        };

        /* the base address and size may be either 32-bit or 64-bit in length.
        the base is the zeroth 64/32-bit word, the size the first */
        match (cells.address, cells.size)
        {
            (1, 1) => total = total + reg.as_multi_u32().ok().unwrap()[1] as usize,
            (2, 2) => total = total + reg.as_multi_u64().ok().unwrap()[1] as usize,
            (base, size) => panic!("Unsupported memory format: base width {} size width {}", base, size)
        }
    }

    return total;
}

/* return true if a stdout device, typically a serial port for debugging, is defined */
fn check_stdout(tree: &DeviceTree) -> bool
{
    if let Ok(node) = tree.get_property(&format!("/chosen"), &format!("stdout-path"))
    {
        if let Ok(path) = node.as_text()
        {
            match tree.get_property(&path, &format!("reg"))
            {
                Ok(_) => return true,
                Err(e) =>  panic!("Can't read debug channel serial port's base address. Reason: {:?}", e)
            }
        }
    }

    false
}

#[test]
fn cpu_core_count()
{
    /* ensure all cores are found: 2 in total */
    let trees = DeviceTrees::new();
    assert!(count_cpu_cores(&trees.rv32) == 2);
    assert!(count_cpu_cores(&trees.rv64) == 2);
}

#[test]
fn ram_count()
{
    /* ensure all RAM is accounted for: 128MiB in total */
    let trees = DeviceTrees::new();
    assert!(count_ram(&trees.rv32) == 128 * 1024 * 1024);
    assert!(count_ram(&trees.rv64) == 128 * 1024 * 1024);
}

#[test]
fn stdout_defined()
{
    /* ensure stdout points to a serial port device */
    let trees = DeviceTrees::new();
    assert!(check_stdout(&trees.rv32));
    assert!(check_stdout(&trees.rv64));
}
