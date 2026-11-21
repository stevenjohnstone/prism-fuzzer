# frozen_string_literal: true

module PrismFuzzer
  module Campaign
    module_function

    def afl_passes_up_to_date?(fuzz_root)
      build_dir = Topology.default_build_dir(fuzz_root)
      afl_dir = File.join(build_dir, "afl")
      stamp = File.join(build_dir, ".fuzz.afl.stamp")
      required = %w[
        SanitizerCoverageLTO.so
        SanitizerCoveragePCGUARD.so
        afl-compiler-rt-armhf.o
        aflpp_driver-armhf.o
        afl-compiler-rt-ppc.o
        aflpp_driver-ppc.o
      ].map { |name| File.join(afl_dir, name) }
      return false unless File.file?(stamp) && required.all? { |p| File.file?(p) && !File.symlink?(p) }

      stamp_mtime = File.mtime(stamp)
      patches = [
        File.join(fuzz_root, "patches", "afl", "aflplusplus.patch"),
        File.join(fuzz_root, "patches", "afl", "aflplusplus_ppc.patch")
      ]
      patches.all? { |p| !File.file?(p) || File.mtime(p) <= stamp_mtime }
    end

    def ensure_afl_passes!(fuzz_root: Topology.locate_fuzz_root, dry_run: false)
      return true if afl_passes_up_to_date?(fuzz_root)

      if dry_run
        puts "[dry-run] patch and build AFL++ LLVM instrumentation passes into build/afl/"
        return true
      end

      build_dir = Topology.default_build_dir(fuzz_root)
      afl_dir = File.join(build_dir, "afl")
      afl_src = File.join(build_dir, "afl-src")
      stamp = File.join(build_dir, ".fuzz.afl.stamp")
      FileUtils.rm_f(stamp)
      Topology.log_progress "patching and building AFL++ instrumentation passes..."
      FileUtils.rm_rf(afl_src)
      FileUtils.mkdir_p([afl_dir, afl_src])

      %w[/AFLplusplus/instrumentation /AFLplusplus/include /AFLplusplus/utils /AFLplusplus/GNUmakefile.llvm].each do |src|
        FileUtils.cp_r(src, afl_src)
      end
      FileUtils.ln_sf("/AFLplusplus/afl-showmap", File.join(afl_src, "afl-showmap"))

      [
        File.join(fuzz_root, "patches", "afl", "aflplusplus.patch"),
        File.join(fuzz_root, "patches", "afl", "aflplusplus_ppc.patch")
      ].each do |patch|
        next unless File.file?(patch)

        Topology.run_cmd("git", "apply", "--unsafe-paths", "--directory=build/afl-src", patch, chdir: fuzz_root)
      end

      Topology.run_cmd("make", "-C", afl_src, "-f", "GNUmakefile.llvm", "LLVM_CONFIG=llvm-config-20", "./SanitizerCoverageLTO.so", "./SanitizerCoveragePCGUARD.so")
      overridden_passes = %w[SanitizerCoverageLTO.so SanitizerCoveragePCGUARD.so]
      Dir.glob("/usr/local/lib/afl/*").each do |entry|
        base = File.basename(entry)
        next if overridden_passes.include?(base)

        FileUtils.ln_sf(entry, File.join(afl_dir, base))
      end
      overridden_passes.each do |so|
        dest = File.join(afl_dir, so)
        FileUtils.rm_f(dest)
        FileUtils.cp(File.join(afl_src, so), dest)
      end

      cross_objs = [
        ["clang", "--target=arm-linux-gnueabihf", "-O2", "-fPIC", "-Wno-unused-result", "-Wno-pointer-sign", "-Wno-tautological-constant-out-of-range-compare", "-I/AFLplusplus/include", "-c", File.join(afl_src, "instrumentation/afl-compiler-rt.o.c"), "-o", File.join(afl_dir, "afl-compiler-rt-armhf.o")],
        ["clang", "--target=arm-linux-gnueabihf", "-O2", "-fPIC", "-I/AFLplusplus/include", "-c", File.join(afl_src, "utils/aflpp_driver/aflpp_driver.c"), "-o", File.join(afl_dir, "aflpp_driver-armhf.o")],
        ["clang", "--target=powerpc-linux-gnu", "-isystem", "/usr/powerpc-linux-gnu/include", "-msecure-plt", "-O2", "-fPIC", "-Wno-unused-result", "-Wno-pointer-sign", "-Wno-tautological-constant-out-of-range-compare", "-I/AFLplusplus/include", "-c", File.join(afl_src, "instrumentation/afl-compiler-rt.o.c"), "-o", File.join(afl_dir, "afl-compiler-rt-ppc.o")],
        ["clang", "--target=powerpc-linux-gnu", "-isystem", "/usr/powerpc-linux-gnu/include", "-msecure-plt", "-O2", "-fPIC", "-I/AFLplusplus/include", "-c", File.join(afl_src, "utils/aflpp_driver/aflpp_driver.c"), "-o", File.join(afl_dir, "aflpp_driver-ppc.o")]
      ]
      cross_objs.each { |cmd| Topology.run_cmd(*cmd) }

      FileUtils.rm_rf(afl_src)
      File.write(stamp, "#{Time.now.utc.iso8601}\n")
      true
    end
  end
end
