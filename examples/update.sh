cd examples; for file in *.new_out; do cp "$file" "${file/new_out/gen_out}";done
