# -*- coding: utf-8 -*-
"""
Created on Sat Jul 22 11:26:40 2023

@author: Manohar
"""

import os
import psutil
import tkinter as tk
from prettytable import PrettyTable
import hashlib
import time
import datetime
def get_disk_space_info():
    disk_info = {}
    partitions = psutil.disk_partitions(all=True)
    for partition in partitions:
        #if partition.mountpoint == "D:\\":
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info[partition.device] = {
                    "Total": usage.total,
                    "Used": usage.used,
                    "Free": usage.free
                }
            except Exception as e:
                print(f"Error getting disk space info for {partition.device}: {e}")
    return disk_info


def get_file_hash(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        # Read the file in chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()



def delete_files_by_extension(folder_path, file_extension):
    files_with_extension = get_files_by_extension(folder_path, file_extension)
    for file_path in files_with_extension:
        try:
            os.remove(file_path)
            print(f"Deleted: {file_path}")
        except OSError as e:
            print(f"Error deleting: {file_path}: {e}")

            

def display_folder_info(folder_path, min_size_in_bytes):
    file_types = {}
    duplicate_files = {}
    disk_info = get_disk_space_info()

    large_files = []  # Temporary list to store large files

    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_extension = os.path.splitext(file)[-1].lower()
            file_size = os.path.getsize(file_path)

            # Count file types
            if file_extension not in file_types:
                file_types[file_extension] = {
                    "Count": 1,
                    "Size": file_size
                }
            else:
                file_types[file_extension]["Count"] += 1
                file_types[file_extension]["Size"] += file_size

            # Find duplicate files
            file_hash = get_file_hash(file_path)
            if file_hash not in duplicate_files:
                duplicate_files[file_hash] = [file_path]
            else:
                duplicate_files[file_hash].append(file_path)

            # Find large files
            if file_size > min_size_in_bytes:
                large_files.append((file_path, file_size))

    # Sort large files list by file sizes in descending order
    large_files.sort(key=lambda x: x[1], reverse=True)
    # Filter out files without duplicates
    duplicate_files = {hash_key: file_list for hash_key, file_list in duplicate_files.items() if len(file_list) > 1}
    
    root = tk.Tk()
    root.title("Folder Information and Disk Space")

    frame = tk.Frame(root, padx=10, pady=5)
    frame.pack()

    tk.Label(frame, text=f"Folder Path: {folder_path}").grid(row=0, column=0, columnspan=2, pady=5)
    tk.Label(frame, text=f"Minimum Size: {convert_bytes_to_readable(min_size_in_bytes)}").grid(row=1, column=0, columnspan=2, pady=5)

    tk.Label(frame, text="Large Files List:").grid(row=2, column=0, columnspan=2, pady=5)
    table_large_files = PrettyTable()
    table_large_files.field_names = ["File Path", "Size"]
    
    table_large_files.align["Size"] = "l"
    
    for file_path, size_in_bytes in large_files:#find_large_files(folder_path, min_size_in_bytes):
        table_large_files.add_row([file_path, convert_bytes_to_readable(size_in_bytes)])
    
    table_large_files_str = table_large_files.get_string()

    # Use Text widget to display the large files list in a scrollable area
    text_widget_large_files = tk.Text(frame, height=10, width=150)
    text_widget_large_files.insert("1.0", table_large_files_str)
    text_widget_large_files.grid(row=3, column=0, columnspan=2)
    text_widget_large_files.config(state="disabled")  # Make the Text widget read-only

    tk.Label(frame, text="File Type Information:").grid(row=4, column=0, columnspan=2, pady=5)

    table_file_types = PrettyTable()
    table_file_types.field_names = ["File Type", "Count", "Size"]
    for file_type, data in file_types.items():
        table_file_types.add_row([file_type, data["Count"], convert_bytes_to_readable(data["Size"])])
    
    table_file_types_str = table_file_types.get_string()

    # Use Text widget to display the file type information in a scrollable area
    text_widget_file_types = tk.Text(frame, height=10, width=100)
    text_widget_file_types.insert("1.0", table_file_types_str)
    text_widget_file_types.grid(row=5, column=0, columnspan=2)
    text_widget_file_types.config(state="disabled")  # Make the Text widget read-only
    
    tk.Label(frame, text="Duplicate Files:").grid(row=6, column=0, columnspan=2, pady=5)

    table_duplicate_files = PrettyTable()
    table_duplicate_files.field_names = ["File Name", "Size", "Duplicates"]

    for hash_key, file_list in duplicate_files.items():
        file_size = os.path.getsize(file_list[0])
        duplicates = "\n".join(file_list[1:])  # Combine duplicate file paths with new lines
        table_duplicate_files.add_row([os.path.basename(file_list[0]), convert_bytes_to_readable(file_size), duplicates])

    table_duplicate_files_str = table_duplicate_files.get_string()

    # Use Text widget to display the duplicate files list in a scrollable area
    text_widget_duplicate_files = tk.Text(frame, height=10, width=150)
    text_widget_duplicate_files.insert("1.0", table_duplicate_files_str)
    text_widget_duplicate_files.grid(row=7, column=0, columnspan=2)
    text_widget_duplicate_files.config(state="disabled")  # Make the Text widget read-only

    root = tk.Tk()
    root.title("Folder Analysis Tool")

    frame = tk.Frame(root, padx=10, pady=5)
    frame.pack()

    tk.Label(frame, text="Enter the folder path you want to analyze:").grid(row=0, column=0, pady=5)

    # Button to trigger the folder analysis
    analyze_button = tk.Button(frame, text="Analyze", command=lambda: display_folder_info(entry_folder_path.get(), get_user_min_file_size_from_gui()))
    analyze_button.grid(row=3, column=0, columnspan=2, pady=5)

    # Button to display files of a specific extension
    display_files_button = tk.Button(frame, text="Display Files by Extension", command=lambda: display_files_by_extension(entry_folder_path.get(), entry_file_extension.get()))
    display_files_button.grid(row=4, column=0, columnspan=2, pady=5)

    # Button to delete files of a specific extension
    delete_files_button = tk.Button(frame, text="Delete Files by Extension", command=lambda: delete_files_by_extension(entry_folder_path.get(), entry_file_extension.get()))
    delete_files_button.grid(row=5, column=0, columnspan=2, pady=5)

    root.mainloop()


def display_disk_space_info():
    disk_info = get_disk_space_info()

    root = tk.Tk()
    root.title("Disk Space Information")

    frame = tk.Frame(root, padx=10, pady=5)
    frame.pack()

    tk.Label(frame, text="Disk Space Information:").grid(row=0, column=0, columnspan=2, pady=5)

    table_disk_space = PrettyTable()
    table_disk_space.field_names = ["Device", "Total", "Used", "Free"]

    for device, space_info in disk_info.items():
        total_space = convert_bytes_to_readable(space_info['Total'])
        used_space = convert_bytes_to_readable(space_info['Used'])
        free_space = convert_bytes_to_readable(space_info['Free'])
        table_disk_space.add_row([device, total_space, used_space, free_space])

    table_disk_space_str = table_disk_space.get_string()

    # Use Text widget to display the disk space information in a scrollable area
    text_widget_disk_space = tk.Text(frame, height=10, width=100)
    text_widget_disk_space.insert("1.0", table_disk_space_str)
    text_widget_disk_space.grid(row=1, column=0, columnspan=2)
    text_widget_disk_space.config(state="disabled")  # Make the Text widget read-only

    root.mainloop()


def convert_bytes_to_readable(bytes_value):
    sizes = ["B", "KB", "MB", "GB", "TB"]
    index = 0
    while bytes_value >= 1024 and index < len(sizes) - 1:
        bytes_value /= 1024
        index += 1
    return f"{bytes_value:.2f} {sizes[index]}"


def get_user_folder_path_from_gui():
    # This function will be called when the user clicks the "Analyze" button
    folder_path = entry_folder_path.get()
    return folder_path

def get_user_min_file_size_from_gui():
    # This function will be called when the user clicks the "Analyze" button
    min_file_size_bytes = int(entry_min_file_size.get())
    return min_file_size_bytes



def get_files_by_extension(folder_path, file_extension):
    files_with_extension = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(file_extension):
                files_with_extension.append(file_path)
    return files_with_extension


def delete_duplicate_files(duplicate_files_list):
    for file_path in duplicate_files_list:
        try:
            os.remove(file_path)
            print(f"Deleted: {file_path}")
        except OSError as e:
            print(f"Error deleting: {file_path}: {e}")
            
            
def display_files_by_extension(folder_path, file_extension):
    files_with_extension = get_files_by_extension(folder_path, file_extension)

    if not files_with_extension:
        result_text = f"No files found with extension {file_extension}"
    else:
        result_text = f"Files with extension {file_extension}:\n"
        result_text += "\n".join(files_with_extension)

    root = tk.Tk()
    root.title(f"Files with extension {file_extension}")

    frame = tk.Frame(root, padx=10, pady=5)
    frame.pack()

    tk.Label(frame, text=result_text).grid(row=0, column=0, pady=5)

    root.mainloop()

def display_duplicates_between_folders(folder_path1, folder_path2):
    duplicates = {}
    
    for root, _, files in os.walk(folder_path1):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = get_file_hash(file_path)
            if file_hash not in duplicates:
                duplicates[file_hash] = [file_path]
    
    duplicate_files_in_folder2 = []
    for root, _, files in os.walk(folder_path2):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = get_file_hash(file_path)
            if file_hash in duplicates:
                duplicate_files_in_folder2.append(file_path)
    
    root = tk.Tk()
    root.title("Duplicate Files Between Folders")

    frame = tk.Frame(root, padx=10, pady=5)
    frame.pack()

    tk.Label(frame, text=f"Folder 1: {folder_path1}").grid(row=0, column=0, columnspan=2, pady=5)
    tk.Label(frame, text=f"Folder 2: {folder_path2}").grid(row=1, column=0, columnspan=2, pady=5)

    tk.Label(frame, text="Duplicate Files in Folder 2:").grid(row=2, column=0, columnspan=2, pady=5)

    table_duplicate_files = PrettyTable()
    table_duplicate_files.field_names = ["File Name", "Size", "Path in Folder 1"]

    for file_path in duplicate_files_in_folder2:
        file_size = os.path.getsize(file_path)
        hash_key = get_file_hash(file_path)
        path_in_folder1 = duplicates[hash_key][0]
        table_duplicate_files.add_row([os.path.basename(file_path), convert_bytes_to_readable(file_size), path_in_folder1])

    table_duplicate_files_str = table_duplicate_files.get_string()

    # Use Text widget to display the duplicate files list in a scrollable area
    text_widget_duplicate_files = tk.Text(frame, height=10, width=150)
    text_widget_duplicate_files.insert("1.0", table_duplicate_files_str)
    text_widget_duplicate_files.grid(row=3, column=0, columnspan=2)
    text_widget_duplicate_files.config(state="disabled")  # Make the Text widget read-only
    # Button to delete duplicate files
    delete_duplicate_button = tk.Button(frame, text="Delete Duplicate Files",
                                        command=lambda: delete_duplicate_files(duplicate_files_in_folder2))
    delete_duplicate_button.grid(row=10, column=0, columnspan=2, pady=5)

    root.mainloop()


def get_inaccessed_files(folder_path, num_days):
    inaccessed_files = []
    current_time = time.time()

    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            last_access_time = os.path.getatime(file_path)

            # Calculate the number of days since the last access
            days_since_access = (current_time - last_access_time) / (24 * 60 * 60)

            if days_since_access > num_days:
                inaccessed_files.append((file_path, days_since_access))

    # Sort inaccessed files list by the number of days since last access in descending order
    inaccessed_files.sort(key=lambda x: x[1], reverse=True)
    return inaccessed_files



def display_inaccessed_files():
    folder_path = entry_folder_path.get()
    num_days = entry_num_days.get()

    try:
        num_days = int(num_days)
        inaccessed_files = get_inaccessed_files(folder_path, num_days)

        root = tk.Tk()
        root.title(f"Inaccessed Files (Last {num_days} Days)")

        frame = tk.Frame(root, padx=10, pady=5)
        frame.pack()

        tk.Label(frame, text=f"Inaccessed Files (Last {num_days} Days):").grid(row=0, column=0, columnspan=2, pady=5)

        table_inaccessed_files = PrettyTable()
        table_inaccessed_files.field_names = ["File Path", "Days Since Last Access"]

        for file_path, days_since_access in inaccessed_files:
            table_inaccessed_files.add_row([file_path, f"{days_since_access:.2f} days"])

        table_inaccessed_files_str = table_inaccessed_files.get_string()

        # Use Text widget to display the inaccessed files list in a scrollable area
        text_widget_inaccessed_files = tk.Text(frame, height=20, width=150)
        text_widget_inaccessed_files.insert("1.0", table_inaccessed_files_str)
        text_widget_inaccessed_files.grid(row=1, column=0, columnspan=2)
        text_widget_inaccessed_files.config(state="disabled")  # Make the Text widget read-only
        # Insert the table string into the Text widget
        text_widget_inaccessed_files.insert("end", table_inaccessed_files_str)

        text_widget_inaccessed_files.config(state="disabled")  # Make the Text widget read-only

        root.mainloop()

    except ValueError:
        # Handle the case where the user entered an invalid number of days
        error_message = "Please enter a valid number of days."
        error_window = tk.Tk()
        error_window.title("Error")
        tk.Label(error_window, text=error_message).pack(padx=10, pady=10)
        error_window.mainloop()
        
        
    
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Folder Analysis Tool")

    frame = tk.Frame(root, padx=10, pady=5)
    frame.pack()

    tk.Label(frame, text="Enter the folder path you want to analyze:").grid(row=0, column=0, pady=5)

    # Entry widget for the user to input the folder path
    entry_folder_path = tk.Entry(frame, width=50)
    entry_folder_path.grid(row=0, column=1, pady=5)

    tk.Label(frame, text="Enter the minimum file size in bytes:").grid(row=1, column=0, pady=5)

    # Entry widget for the user to input the minimum file size in bytes
    entry_min_file_size = tk.Entry(frame, width=15)
    entry_min_file_size.grid(row=1, column=1, pady=5)

    tk.Label(frame, text="Enter the file extension (e.g., .rar, .pdf):").grid(row=2, column=0, pady=5)

    # Entry widget for the user to input the file extension
    entry_file_extension = tk.Entry(frame, width=10)
    entry_file_extension.grid(row=2, column=1, pady=5)

    # Button to trigger the folder analysis
    analyze_button = tk.Button(frame, text="Analyze", command=lambda: display_folder_info(entry_folder_path.get(), get_user_min_file_size_from_gui()))
    analyze_button.grid(row=3, column=0, columnspan=2, pady=5)

    # Button to display files of a specific extension
    display_files_button = tk.Button(frame, text="Display Files by Extension", command=lambda: display_files_by_extension(entry_folder_path.get(), entry_file_extension.get()))
    display_files_button.grid(row=4, column=0, columnspan=2, pady=5)

    # Button to delete files of a specific extension
    delete_files_button = tk.Button(frame, text="Delete Files by Extension", command=lambda: delete_files_by_extension(entry_folder_path.get(), entry_file_extension.get()))
    delete_files_button.grid(row=5, column=0, columnspan=2, pady=5)

    # Button to display disk space information
    disk_space_button = tk.Button(frame, text="Display Disk Space", command=display_disk_space_info)
    disk_space_button.grid(row=6, column=0, columnspan=2, pady=5)

    # Label and Entry widgets for folder path input for displaying duplicates between folders
    tk.Label(frame, text="Enter Folder 1 Path:").grid(row=7, column=0, pady=5)
    entry_folder_path1 = tk.Entry(frame, width=50)
    entry_folder_path1.grid(row=7, column=1, pady=5)

    tk.Label(frame, text="Enter Folder 2 Path:").grid(row=8, column=0, pady=5)
    entry_folder_path2 = tk.Entry(frame, width=50)
    entry_folder_path2.grid(row=8, column=1, pady=5)

    # Button to display duplicates between folders
    display_duplicates_button = tk.Button(frame, text="Display Duplicates Between Folders",
                                         command=lambda: display_duplicates_between_folders(entry_folder_path1.get(), entry_folder_path2.get()))
    display_duplicates_button.grid(row=9, column=0, columnspan=2, pady=5)
    # Button to display duplicates between folders
    display_duplicates_button = tk.Button(frame, text="Display Duplicates Between Folders",
                                         command=lambda: display_duplicates_between_folders(entry_folder_path1.get(), entry_folder_path2.get()))
    display_duplicates_button.grid(row=9, column=0, columnspan=2, pady=5)
    tk.Label(frame, text="Enter the number of days for inaccessed files:").grid(row=11, column=0, pady=5)
    entry_num_days = tk.Entry(frame, width=10)
    entry_num_days.grid(row=11, column=1, pady=5)

    display_inaccessed_button = tk.Button(frame, text="Display Inaccessed Files", command=display_inaccessed_files)
    display_inaccessed_button.grid(row=12, column=0, columnspan=2, pady=5)

    root.mainloop()        