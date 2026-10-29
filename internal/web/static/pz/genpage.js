// The generator page.
import { generatorPanel } from "./genui.js";
import { loadTexts, wireLogout } from "./common.js";

await loadTexts();
document.getElementById("pz-generator").append(generatorPanel());
wireLogout();
