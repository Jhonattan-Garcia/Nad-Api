# Display.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
import webbrowser
import csv

def display_results(parent_window, output_folder):
    urlscan_path = os.path.join(output_folder, "Current_UrlScan_results.json")
    vt_path = os.path.join(output_folder, "Current_VT_results.json")

    if not (os.path.exists(urlscan_path) and os.path.exists(vt_path)):
        messagebox.showerror("Error", "No se encontraron los archivos de resultados.")
        return

    try:
        with open(urlscan_path, "r", encoding="utf-8") as f:
            urlscan_results = json.load(f)
        with open(vt_path, "r", encoding="utf-8") as f:
            vt_results = json.load(f)
    except Exception as e:
        messagebox.showerror("Error", f"No se pudieron cargar los resultados: {e}")
        return

    result_window = tk.Toplevel(parent_window)
    result_window.title("Results")
    result_window.geometry("800x400")

    # ----- FRAME SUPERIOR PARA BOTÓN DE EXPORTACIÓN -----
    top_frame = tk.Frame(result_window)
    top_frame.pack(fill="x", padx=5, pady=5)

    # Botón para exportar resultados
    export_button = tk.Button(top_frame, text="Exportar CSV", command=lambda: export_to_csv(result_window, result_table))
    export_button.pack(side="right")

    # ----- TABLA DE RESULTADOS -----
    columns = (
        "Criteria", 
        "Task URL", 
        "Task Time", 
        "Page Status",
        "Screenshot", 
        "Task ID", 
        "Last Analysis Date", 
        "Creation Date"
    )
    result_table = ttk.Treeview(result_window, columns=columns, show="headings")

    for col in columns:
        result_table.heading(col, text=col)
        result_table.column(col, width=100, anchor="center")
    
    result_table.pack(fill="both", expand=True)

    # Llenar la tabla
    for entry in urlscan_results:
        criteria = entry.get("search_criteria", "N/A")
        task_url = entry.get("task_url", "N/A")
        task_time = entry.get("task_time", "N/A")
        page_status = entry.get("page_status", "N/A")
        screenshot = entry.get("screenshot", "N/A")
        task_id = entry.get("task_id", "N/A")
        
        vt_entry = next(
            (item for item in vt_results if item.get("search_criteria") == criteria),
            {}
        )
        last_analysis_date = vt_entry.get("last_analysis_date", "N/A")
        creation_date = vt_entry.get("creation_date", "N/A")
        
        result_table.insert(
            "",
            "end",
            values=(
                criteria,
                task_url,
                task_time,
                page_status,
                screenshot,
                task_id,
                last_analysis_date,
                creation_date
            )
        )
    
    # Indices de columnas con enlaces
    TASK_URL_INDEX = 1
    SCREENSHOT_INDEX = 4

    # ========== Doble clic para abrir enlaces ==========
    def on_double_click(event):
        region = result_table.identify("region", event.x, event.y)
        row_id = result_table.identify_row(event.y)
        col_id = result_table.identify_column(event.x)

        if region == "cell" and row_id and col_id:
            values = result_table.item(row_id, "values")
            col_index = int(col_id.replace('#', '')) - 1
            if col_index in [TASK_URL_INDEX, SCREENSHOT_INDEX]:
                url = values[col_index]
                if url and url not in ("N/A", "null"):
                    webbrowser.open(url)

    result_table.bind("<Double-1>", on_double_click)
    
    # ========== Menú contextual para copiar ==========
    context_menu = tk.Menu(result_window, tearoff=0)
    context_menu.add_command(label="Copiar")

    def copy_to_clipboard(text):
        result_window.clipboard_clear()
        result_window.clipboard_append(text)
        # Forzar que el S.O. reciba el nuevo contenido
        result_window.update()

    def on_right_click(event):
        region = result_table.identify("region", event.x, event.y)
        row_id = result_table.identify_row(event.y)
        col_id = result_table.identify_column(event.x)

        if region == "cell" and row_id and col_id:
            col_index = int(col_id.replace('#','')) - 1
            values = result_table.item(row_id, "values")
            if col_index < len(values):
                cell_value = values[col_index]
                context_menu.entryconfigure(
                    "Copiar", 
                    command=lambda val=cell_value: copy_to_clipboard(val)
                )
                context_menu.post(event.x_root, event.y_root)

    result_table.bind("<Button-3>", on_right_click)


def export_to_csv(result_window, result_table):
    """
    Muestra un diálogo para guardar el contenido de la tabla como CSV.
    """
    file_path = filedialog.asksaveasfilename(
        parent=result_window,
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        title="Guardar resultados como CSV"
    )
    if not file_path:
        return  # Usuario canceló

    # Obtener las columnas que definimos en la tabla
    columns = result_table["columns"]

    # Guardar filas de la tabla en CSV
    try:
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, delimiter=",")
            # Escribir encabezados
            writer.writerow(columns)
            # Escribir cada fila
            for row_id in result_table.get_children():
                row_values = result_table.item(row_id, "values")
                writer.writerow(row_values)
        messagebox.showinfo("Exportar CSV", f"Resultados exportados con éxito a {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo exportar a CSV:\n{e}")
