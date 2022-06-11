# Go to source directory
cd ~/srcCode/rust/

# Part suggested by Raoul: ---------------------------------------------
# cargo install fortanix-sgx-tools --force --locked

# RAOUL: Hier kun je dus aangeven dat rust-ldd gebouwd moet worden
./configure --enable-lld --disable-rpath --set llvm.ninja=false

if [ -d "src/libstd" ]; then
    libstd_path="src/libstd"
elif [ -d "library/std" ]; then
    libstd_path="library/std"
else
    echo "No standard library directory found"
    exit 1
fi

# RAOUL: We geven hier aan welk target er gebouwd moet worden. Dat had waarschijnlijk ook allemaal in de `configure` meegegeven kunnen worden
# --host='' is because of https://github.com/rust-lang/rust/issues/83661, and
# should be removed once that issue is resolved
# python3 ./x.py test --stage=1 -i --target=x86_64-fortanix-unknown-sgx "$libstd_path" --host='' --no-doc --exclude --no-fail-fast src/tools/linkchecker 2>&1
python3 ./x.py test --stage=1 -i --target=x86_64-fortanix-unknown-sgx "$libstd_path" --host='' --no-doc --exclude src/tools/linkchecker 2>&1

# Additions from Arthur: ------------------------------------------------
# Set the newly built stage as default
rustup default stage1

# cd ~/Documents/Programming_Projects/rust/test_abi_changes/
cd ~/Documents/MA2/Thesis/Development/test-app/
# See if our test program still succesfully compiles
cargo +stage1 run --target x86_64-fortanix-unknown-sgx

# Go back to first directory
cd ~/srcCode/rust/

# Notify user that testing has finished
notify-send -u critical "Rust compilation & testing process finished!"
