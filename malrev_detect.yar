rule Linux_Ransomware_Malrev_Obfuscated {
    meta:
        description = "Mendeteksi Ransomware Malrev (Varian Obfuscated)"
        author = "Salvado & Marck"
        date = "2026"
        severity = "Critical"
        note = "Mendeteksi string yang sengaja disisipi karakter 'H' untuk menghindari deteksi standar"

    strings:
        // String Kriptografi 
        $crypto = "EVP_aes_128_gcm" ascii

        // String Obfuscated 
        // Malware menyisipkan 'H' atau memotong string
        $obf_vm1 = "VirtualBH" ascii  // Aslinya: VirtualBox
        $obf_vm2 = "VMwa" ascii       // Aslinya: VMware (terpotong)
        $obf_doc = "/.dockerH" ascii  // Aslinya: /.dockerenv
        
        // Artefak Path Sistem yang Rusak
        // Terlihat di dump: /sys/claH ss/dmi...
        $broken_path1 = "/sys/claH" ascii 
        $broken_path2 = "id/produH" ascii

    condition:
        // Header ELF (Linux)
        uint32(0) == 0x464c457f and
        
        // Harus ada fungsi enkripsi
        $crypto and
        

        (1 of ($obf_*) or 1 of ($broken_path*))
}
