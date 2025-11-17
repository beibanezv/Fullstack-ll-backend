import express from "express";
import cors from "cors";
const app = express();
app.use(cors());
app.use(express.json());
const PORT = 5000;
app.get("/api/mensaje", (req, res) => {
res.json({
mensaje: "Hola desde el backend"
})
})

app.listen(PORT, () => {
	console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
