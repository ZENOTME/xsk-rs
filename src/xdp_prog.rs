//! Used to regsiter xdp program.

// GLOBAL: HashMap<(sting,usize),XdpProgram>
// register(string,usize,file_name)
//
// each xdp program contains a map, map from u64 to socket
// this map must call "xdp_map" and must be a hash map
// use socket before:
// update_map(u64,Socket)

use std::{collections::HashMap, ffi::CString, io, ptr, sync::Mutex};

use libxdp_sys::{xdp_attach_mode, xdp_attach_mode_XDP_MODE_UNSPEC, xdp_program, xsk_socket};
use once_cell::sync::Lazy;
use std::io::Result;

const XSK_MAP_NAME: &str = "xsks_map";

// A global variable to store all xdp programs
// It map interface name to xdp program
static GLOBAL_XDP_PROGRAMS: Lazy<Mutex<HashMap<String, XdpProgram>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

struct XdpProgram {
    // Only used in drop
    xdp_prog: u64,
    xsk_map_fd: i32,
    attch_mode: xdp_attach_mode,
    if_index: i32,
}

impl XdpProgram {
    pub(crate) fn update_map(&self, socket: *mut xsk_socket) -> Result<()> {
        let err = unsafe { libxdp_sys::xsk_socket__update_xskmap(socket, self.xsk_map_fd) };
        if err != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Fail to update map in xdp program.",
            ));
        }
        Ok(())
    }

    // #TODO
    // Update the value to -1 when the SockerInner drop
}

impl Drop for XdpProgram {
    fn drop(&mut self) {
        let xdp_prog = self.xdp_prog as *mut xdp_program;
        let err =
            unsafe { libxdp_sys::xdp_program__detach(xdp_prog, self.if_index, self.attch_mode, 0) };
        if err != 0 {
            eprintln!("Fail to detach xdp program. Error code: {}", err);
        }
    }
}

/// Register a xdp program into the global xdp programs.
pub fn regsiter_xdp_program(file_name: &str, section_name: &str, if_name: &str) -> Result<()> {
    let file_name = CString::new(file_name)?;
    let section_name = if !section_name.is_empty() {
        CString::new(section_name)?.as_c_str().as_ptr()
    } else {
        ptr::null()
    };
    let if_index = unsafe { libc::if_nametoindex(CString::new(if_name)?.as_c_str().as_ptr()) };
    if if_index == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "No such interface"));
    }

    // Create xdp program
    let xdp_prog = unsafe {
        libxdp_sys::xdp_program__open_file(
            file_name.as_c_str().as_ptr(),
            section_name,
            ptr::null_mut(),
        )
    };
    if xdp_prog.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Fail to open xdp program. Return null pointer.",
        ));
    }
    let err = unsafe { libxdp_sys::libxdp_get_error(xdp_prog as *const _) };
    if err != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Fail to open xdp program. Error code: {}", err),
        ));
    }

    // Attach xdp program
    let err = unsafe {
        libxdp_sys::xdp_program__attach(
            xdp_prog,
            if_index as i32,
            xdp_attach_mode_XDP_MODE_UNSPEC,
            0,
        )
    };
    if err != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Fail to attach xdp program. Error code: {}", err),
        ));
    }

    // Get the map from xdp program
    let map = unsafe {
        libxdp_sys::bpf_object__find_map_by_name(
            libxdp_sys::xdp_program__bpf_obj(xdp_prog),
            CString::new(XSK_MAP_NAME).unwrap().as_c_str().as_ptr(),
        )
    };
    let xsk_map_fd = unsafe { libxdp_sys::bpf_map__fd(map) };
    if xsk_map_fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Fail to get map from xdp program.",
        ));
    }

    let xdp_program = XdpProgram {
        xdp_prog: xdp_prog as u64,
        xsk_map_fd,
        attch_mode: xdp_attach_mode_XDP_MODE_UNSPEC,
        if_index: if_index as i32,
    };

    GLOBAL_XDP_PROGRAMS
        .lock()
        .unwrap()
        .insert(if_name.to_string(), xdp_program);

    Ok(())
}

pub fn update_map_in_xdp_program(if_name: &str, socket: *mut xsk_socket) -> Result<()> {
    GLOBAL_XDP_PROGRAMS
        .lock()
        .unwrap()
        .get(if_name)
        .ok_or(io::Error::new(
            io::ErrorKind::NotFound,
            "No such xdp program",
        ))?
        .update_map(socket)?;
    Ok(())
}
