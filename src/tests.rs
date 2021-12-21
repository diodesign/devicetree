/* Device tree blob parsing and writing
 *
 * Unit tests
 * 
 * TODO: Generate DTBs on the fly from qemu and parse them
 * 
 * (c) Chris Williams, 2020-2021.
 *
 * See LICENSE for usage and copying.
 */

use std::path::Path;
use std::fs::read;
use super::{DeviceTree, DeviceTreeBlob};

/* describe a sample file and its config */
struct SampleFile
{
    pub cpus: usize,
    pub ram_size: usize,
    pub filename: &'static str 
}

/* list of DTB samples we'll use to test */
const SAMPLES: [SampleFile; 3] = [
    SampleFile
    {
        cpus: 2,
        ram_size: 128 * 1024 * 1024,
        filename: "samples/qemu-rv32-virt-smp2-m128.dtb"
    },
    
    SampleFile
    {
        cpus: 2,
        ram_size: 128 * 1024 * 1024,
        filename: "samples/qemu-rv64-virt-smp2-m128.dtb"
    },

    SampleFile
    {
        cpus: 4,
        ram_size: 512 * 1024 * 1024,
        filename: "samples/sifive-rv64-u-smp4-m512.dtb"
    }
];

struct SampleDeviceTree
{
    pub cpus: usize,
    pub ram_size: usize,
    pub dt: DeviceTree   
}

struct DeviceTrees
{
    parsed: Vec<SampleDeviceTree>
}

impl DeviceTrees
{
    pub fn new() -> DeviceTrees
    {
        let mut trees: Vec<SampleDeviceTree> = Vec::new();

        /* parse each of the sample files in SAMPLES and
           store their trees and expected config values in
           an array to pass back to the caller */
        for sample in SAMPLES.iter()
        {
            match DeviceTreeBlob::from_slice(DeviceTrees::read_bytes(sample.filename).as_slice())
            {
                Ok(blob) => match blob.to_parsed()
                {
                    Ok(dt) => trees.push(SampleDeviceTree
                    {
                        cpus: sample.cpus,
                        ram_size: sample.ram_size,
                        dt: dt
                    }),
                    Err(error_type) => panic!("Couldn't parse device tree {}: {:?}", sample.filename, error_type)
                },
                Err(error_type) => panic!("Couldn't create blob from slice {}: {:?}", sample.filename, error_type)
            }
        }

        DeviceTrees
        {
            parsed: trees
        }
    }

    pub fn iter(&self) -> std::slice::Iter<'_, SampleDeviceTree>
    {
        self.parsed.iter()
    }

    pub fn read_bytes(filename: &str) -> Vec<u8>
    {
        let path = Path::new(filename);
        match read(&path)
        {
            Ok(bytes) => bytes,
            Err(error_type) => panic!("Couldn't read contents of {}: {:?}", path.display(), error_type)
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
    /* ensure all cores are found */
    for tree in DeviceTrees::new().iter()
    {
        assert!(count_cpu_cores(&tree.dt) == tree.cpus);    
    }
}

#[test]
fn ram_count()
{
    /* ensure all RAM is accounted for */
    for tree in DeviceTrees::new().iter()
    {
        assert!(count_ram(&tree.dt) == tree.ram_size);    
    }
}

#[test]
fn stdout_defined()
{
    /* ensure stdout points to a serial port device */
    for tree in DeviceTrees::new().iter()
    {
        assert!(check_stdout(&tree.dt));    
    }
}

#[test]
fn test_own_dtb()
{
    /* load DTBs from disk and parse them into trees */
    let trees = DeviceTrees::new();

    for tree in trees.iter()
    {
        /* then convert trees back into blobs using our code */
        let bytes = tree.dt.to_blob();
        assert_eq!(bytes.is_ok(), true);

        let dtb = DeviceTreeBlob::from_slice(bytes.unwrap().as_slice());
        assert_eq!(dtb.is_ok(), true);

        /* now parse them again from DTB to trees to test our DTB generation code is sound */
        let parsed = dtb.unwrap().to_parsed();
        assert_eq!(parsed.is_ok(), true);

        let parsed = parsed.unwrap();

        /* perform checks */
        /* should be two CPU cores each */
        assert!(count_cpu_cores(&parsed) == tree.cpus);

        /* should be 128MiB of RAM each */
        assert!(count_ram(&parsed) == tree.ram_size);

        /* stdout should point to a serial device */
        assert!(check_stdout(&parsed));
    }
}