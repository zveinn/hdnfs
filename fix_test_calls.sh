#!/bin/bash
# Fix function calls in test files to handle errors

for file in consistency_test.go crypt_test.go meta_test.go operations_test.go integration_test.go largefile_test.go list_test.go overwrite_test.go sync_test.go; do
    if [ -f "$file" ]; then
        # Fix InitMeta calls
        sed -i 's/\tInitMeta(\([^)]*\))/\tif err := InitMeta(\1); err != nil {\n\t\tt.Fatalf("InitMeta failed: %v", err)\n\t}/g' "$file"
        
        # Fix Add calls  
        sed -i 's/\tAdd(\([^)]*\))/\tif err := Add(\1); err != nil {\n\t\tt.Fatalf("Add failed: %v", err)\n\t}/g' "$file"
        
        # Fix Del calls
        sed -i 's/\tDel(\([^)]*\))/\tif err := Del(\1); err != nil {\n\t\tt.Fatalf("Del failed: %v", err)\n\t}/g' "$file"
        
        # Fix Sync calls
        sed -i 's/\tSync(\([^)]*\))/\tif err := Sync(\1); err != nil {\n\t\tt.Fatalf("Sync failed: %v", err)\n\t}/g' "$file"
    fi
done
