# @koove/secrets-cli

CLI para gestionar credenciales encriptadas con conexión VPN obligatoria.

## Instalación
```bash
npm install -g @koove/secrets-cli
```
## Uso
```bash
koove-secrets --help
```

---

### **🛠️ 2. Estructura Inicial de la CLI**
#### **A. Estructura de Archivos**

koove-secrets-cli/
├── bin/
│ └── cli.js # Punto de entrada
├── src/
│ ├── commands/ # Lógica de comandos (ej: set-credential.js)
│ └── utils/ # Helpers (encriptación, logs)
├── package.json # Config de npm
└── README.md # Documentación


#### **B. Contenido de `bin/cli.js`**
```javascript
#!/usr/bin/env node
const { program } = require('commander');

program
  .name('koove-secrets')
  .description('CLI para gestionar credenciales seguras con Koove')
  .version('1.0.0');

// Comando de prueba
program
  .command('test')
  .description('Verifica que la CLI funcione')
  .action(() => console.log('✅ CLI operativa!'));

program.parse(process.argv);