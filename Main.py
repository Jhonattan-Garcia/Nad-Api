import tkinter as tk
from tkinter import ttk, messagebox
import json
import re
import threading
import subprocess
import os

# Importa el módulo que mostrará la ventana de resultados
import Display

def load_config():
    """Carga la configuración desde config.json."""
    try:
        with open("config.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        messagebox.showerror("Error", "No se encontró config.json.")
        return {}

def extract_domain(url):
    """Extrae el dominio de una URL, eliminando protocolo y rutas."""
    url = url.strip()
    url = re.sub(r'^https?://', '', url)
    url = url.split('/')[0]
    return url

def is_ip(value):
    """Verifica si la cadena corresponde al formato de dirección IP."""
    return re.match(r'\d+\.\d+\.\d+\.\d+$', value) is not None

def process_input(text_input_widget, table_widget):
    """Lee el texto de entrada y lo muestra en la tabla, clasificando dominio/IP."""
    text = text_input_widget.get("1.0", tk.END).strip()
    lines = text.split("\n")
    data = []
    
    for line in lines:
        if line.strip():
            domain_or_ip = extract_domain(line)
            dtype = "ip" if is_ip(domain_or_ip) else "domain"
            data.append((domain_or_ip, dtype))
    
    update_table(table_widget, data)

def update_table(table_widget, data):
    """Borra el contenido previo de la tabla y agrega nuevos registros."""
    for row in table_widget.get_children():
        table_widget.delete(row)
    
    for domain, dtype in data:
        table_widget.insert("", "end", values=(domain, dtype))

def save_to_json(table_widget, output_folder):
    """Guarda los datos de la tabla en un archivo JSON."""
    data = []
    for row in table_widget.get_children():
        values = table_widget.item(row, "values")
        data.append({"type": values[1], "value": values[0]})
    
    output_path = os.path.join("criteria.json")
    with open(output_path, "w") as f:
        json.dump({"search_criteria": data}, f, indent=4)
    
    messagebox.showinfo("Guardado", f"Datos guardados en {output_path}")

def run_parallel_scans(root, output_folder, progress_label, progress_bar):
    """
    Lanza en hilos separados los scripts (VirusTotal.py y UrlScan.py).
    Cuando terminen, se llama al hilo principal para detener el progress bar
    y luego abrir la ventana de Display.py para ver resultados.
    """
    
    def run_scans():
        threads = []
        for script in ["VirusTotal.py", "UrlScan.py"]:
            if os.path.exists(script):
                thread = threading.Thread(target=lambda: subprocess.run(["python", script]))
                threads.append(thread)
                thread.start()
        
        # Esperar a que terminen los hilos
        for thread in threads:
            thread.join()
        
        # Cuando terminen, usamos 'root.after()' para actualizar la GUI en el hilo principal
        root.after(0, on_scans_completed)

    def on_scans_completed():
        """
        Se ejecuta una vez que finalizan los hilos de escaneo (en el hilo principal).
        """
        progress_bar.stop()
        progress_label.pack_forget()
        progress_bar.pack_forget()
        
        messagebox.showinfo("Completado", "Análisis finalizado. Mostrando resultados...")
        
        # Se llama a Display.py para mostrar la segunda ventana con la tabla de resultados
        Display.display_results(root, output_folder)

    # Iniciar barra de progreso y correr hilos
    progress_label.pack()
    progress_bar.pack()
    progress_bar.start()
    threading.Thread(target=run_scans).start()

def open_settings(root, config_data):
    """Muestra una ventana para editar la configuración cargada desde config.json."""
    if not config_data:
        return
    
    settings_window = tk.Toplevel(root)
    settings_window.title("Settings")
    settings_window.geometry("400x300")
    settings_window.configure(padx=20, pady=20)
    
    fields = {}
    
    def save_settings():
        for key, entry in fields.items():
            config_data[key] = entry.get()
        with open("config.json", "w") as f:
            json.dump(config_data, f, indent=4)
        settings_window.destroy()
    
    row = 0
    for key, value in config_data.items():
        tk.Label(settings_window, text=key).grid(row=row, column=0, sticky="w", padx=5, pady=5)
        entry = tk.Entry(settings_window, width=30)
        entry.grid(row=row, column=1, padx=5, pady=5)
        entry.insert(0, str(value))
        fields[key] = entry
        row += 1
    
    save_btn = tk.Button(settings_window, text="Save", command=save_settings)
    save_btn.grid(row=row, column=0, columnspan=2, pady=10)

def main():
    """Función principal que crea la ventana de la primera interfaz."""
    config = load_config()
    output_folder = config.get("output_folder", ".")

    root = tk.Tk()
    root.title("URL and IP Processor")
    root.geometry("600x500")
    root.configure(padx=20, pady=20)
    
    frame = tk.Frame(root)
    frame.pack(pady=10, padx=10, fill="both", expand=True)
    
    progress_label = tk.Label(frame, text="Ejecutando análisis... Por favor, espera.")
    progress_bar = ttk.Progressbar(frame, mode="indeterminate")
    
    btn_frame = tk.Frame(frame)
    btn_frame.pack(pady=5)
    
    # Botón de Ajustes
    settings_btn = tk.Button(btn_frame, text="Settings",
                             command=lambda: open_settings(root, config),
                             width=10)
    settings_btn.grid(row=0, column=0, padx=5)
    
    # Botón para ejecutar
    def execute_action():
        process_input(text_input, table)
        save_to_json(table, output_folder)
        run_parallel_scans(root, output_folder, progress_label, progress_bar)
    
    execute_btn = tk.Button(btn_frame, text="Execute",
                            command=execute_action,
                            width=20)
    execute_btn.grid(row=0, column=1, padx=5)
    
    # Campo de texto donde se pegan dominios/IP
    text_input = tk.Text(frame, height=10, width=60)
    text_input.pack(pady=5)
    
    # Tabla para mostrar URL/IP clasificadas
    table = ttk.Treeview(frame, columns=("Value", "Type"), show="headings", height=10)
    table.heading("Value", text="Value")
    table.heading("Type", text="Type")
    table.pack(pady=5)
    
    root.mainloop()

if __name__ == "__main__":
    main()
