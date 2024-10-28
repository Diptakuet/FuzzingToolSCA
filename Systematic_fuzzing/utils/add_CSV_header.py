import csv

def add_csv_header(input_file_path, output_file_path, header=[]):
    # Read the existing data
    with open(input_file_path, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        data = list(reader)

    # Add the new header at the beginning of the data list
    data.insert(0, header)

    # Write the modified data to a new file
    with open(output_file_path, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerows(data)
