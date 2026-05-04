// Helper tool to build the kernel driver using Windows native process creation
// Usage: cargo run --bin build-driver

fn main() {
    let wdk_dir = r"C:\Program Files (x86)\Windows Kits\10";
    let sdk_ver = "10.0.26100.0";
    let msvc_root = r"D:\c+\VC\Tools\MSVC\14.50.35717";
    let src_dir = r"D:\work\KongBaiware\LouisMod\louismod-kdriver\driver";
    let build_dir = format!(r"{}\build", src_dir);
    let obj_dir = format!(r"{}\obj", build_dir);
    let bin_dir = format!(r"{}\bin", build_dir);

    // Create directories
    std::fs::create_dir_all(&obj_dir).ok();
    std::fs::create_dir_all(&bin_dir).ok();

    // Set environment variables
    std::env::set_var("PATH", format!(r"{}\bin\Hostx64\x64;{}", msvc_root, std::env::var("PATH").unwrap_or_default()));
    std::env::set_var("INCLUDE", format!(
        r"{}\include;{}\\atlmfc\\include;{}\\Include\\{}\km;{}\\Include\\{}\shared;{}\\Include\\{}\um;{}\\Include\\{}\ucrt",
        msvc_root, msvc_root, wdk_dir, sdk_ver, wdk_dir, sdk_ver, wdk_dir, sdk_ver, wdk_dir, sdk_ver
    ));
    std::env::set_var("LIB", format!(
        r"{}\lib\x64;{}\\atlmfc\\lib\x64;{}\\Lib\\{}\km\x64;{}\\Lib\\{}\um\x64",
        msvc_root, msvc_root, wdk_dir, sdk_ver, wdk_dir, sdk_ver
    ));

    // Source files
    let sources = &["driver.c", "init.c", "ioctl.c", "memory.c", "process.c", "input.c", "hiding.c"];
    let mut objs = Vec::new();

    let cflags = format!(
        "/nologo /c /kernel /W4 /WX- /O2 /GS /GF /Gy /Zp8 \
         /I{src} \
         /I\"{wdk}\\Include\\{sdk}\\km\" \
         /I\"{wdk}\\Include\\{sdk}\\shared\" \
         /I\"{wdk}\\Include\\{sdk}\\um\" \
         /I\"{wdk}\\Include\\{sdk}\\ucrt\" \
         /DKERNEL_MODE /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00",
         src = src_dir, wdk = wdk_dir, sdk = sdk_ver
    );

    for src in sources {
        let src_path = format!(r"{}\{}", src_dir, src);
        let obj_name = format!("{}_x64.obj", src.trim_end_matches(".c"));
        let obj_path = format!(r"{}\{}", obj_dir, obj_name);

        println!("[COMPILE] {}", src);
        let status = std::process::Command::new("cl.exe")
            .args(cflags.split_whitespace())
            .arg(format!("/Fo\"{}\"", obj_path))
            .arg(&src_path)
            .status()
            .expect("failed to execute cl.exe");

        if !status.success() {
            eprintln!("[ERROR] Compilation failed: {}", src);
            std::process::exit(1);
        }
        objs.push(obj_path);
    }

    let sys_file = format!(r"{}\louismod.sys", bin_dir);
    let ldflags = format!(
        "/nologo /kernel /subsystem:native /driver /entry:DriverEntry \
         /MACHINE:x64 /align:64 /OPT:REF /OPT:ICF /NXCOMPAT \
         /LIBPATH:\"{wdk}\\Lib\\{sdk}\\km\\x64\" \
         /LIBPATH:\"{wdk}\\Lib\\{sdk}\\um\\x64\" \
         ntoskrnl.lib hal.lib",
         wdk = wdk_dir, sdk = sdk_ver
    );

    println!("[LINK] louismod.sys");
    let mut cmd = std::process::Command::new("link.exe");
    cmd.args(ldflags.split_whitespace());
    cmd.arg(format!("/OUT:\"{}\"", sys_file));
    for obj in &objs {
        cmd.arg(obj);
    }

    let status = cmd.status().expect("failed to execute link.exe");
    if !status.success() {
        eprintln!("[ERROR] Linking failed");
        std::process::exit(1);
    }

    // Copy to release directory
    let target = r"D:\work\KongBaiware\LouisMod\target\release\louismod.sys";
    std::fs::copy(&sys_file, target).expect("failed to copy driver");

    println!("[DONE] Driver built: {}", sys_file);
    println!("[COPY] Copied to: {}", target);
}
