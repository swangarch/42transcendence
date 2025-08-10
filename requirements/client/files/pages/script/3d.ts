declare const BABYLON : any;
declare var game : gameData;

// IGNORE CHECK GPU-------------------------------------------------------------

const originalGetExtension1 = WebGLRenderingContext.prototype.getExtension;
const originalGetExtension2 = WebGL2RenderingContext.prototype.getExtension;

WebGLRenderingContext.prototype.getExtension = function(name) {
  if (name === 'WEBGL_debug_renderer_info') {
    return null;
  }
  return originalGetExtension1.call(this, name);
};

WebGL2RenderingContext.prototype.getExtension = function(name) {
  if (name === 'WEBGL_debug_renderer_info') {
    return null;
  }
  return originalGetExtension2.call(this, name);
};

// IGNORE CHECK GPU-------------------------------------------------------------

var ballSize = 0.5;
var siteLength = 15;
var siteWidth = 10;
var padSize = 2.5;

const canvas = document.getElementById("renderCanvas")! as HTMLCanvasElement;
// GLOBAL-------------------------------------------------------------

canvas.addEventListener("mousedown", (e) => {
  e.preventDefault();
  window.scrollTo(0, 0);
});

canvas.addEventListener('focus', (e) => {
  window.scrollTo(0, 0);
});

document.addEventListener("wheel", (e) => {
  e.preventDefault(); // prevent page rotation
}, { passive: false });

document.addEventListener("keyup", (e) => {
  if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(e.key)) {
    e.preventDefault();
  }
}, { passive: false });

document.addEventListener("keydown", (e) => {
  if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(e.key)) {
    e.preventDefault();
  }
}, { passive: false });

const engine = new BABYLON.Engine(canvas, true, {
  preserveDrawingBuffer: true, 
  stencil: true, 
  antialias: true 
});

function resizeCanvasForHiDPI() {
  const ratio = window.devicePixelRatio || 1;

  canvas.width = canvas.clientWidth * ratio;
  canvas.height = canvas.clientHeight * ratio;
  engine.resize();
}

resizeCanvasForHiDPI();
window.addEventListener("resize", resizeCanvasForHiDPI);

engine.setHardwareScalingLevel(1);

const scene = new BABYLON.Scene(engine);

scene.clearColor = new BABYLON.Color3(0.9, 0.92, 0.95);

// GLOBAL-------------------------------------------------------------



// CAMERA-------------------------------------------------------------
const camera = new BABYLON.ArcRotateCamera(
  "camera1",
  Math.PI / 2 * 3,      // alpha: angle for y axis
  Math.PI / 4 * 0.5,      // beta：angle for x axis
  30,               // radius：distance between target and camera
  new BABYLON.Vector3(0, 0, 0), // target point
  scene
);

// open mouse control
camera.attachControl(canvas, true);
camera.inputs.attached.pointers.buttons = [0];
camera.panningSensibility = 0;

// limit camera
camera.lowerBetaLimit = 0.1;      // prevent camera lower than ground
camera.upperBetaLimit = Math.PI / 2; // prevent camera over rotate
camera.lowerRadiusLimit = 5;      // min zoom
camera.upperRadiusLimit = 40;    // max zoom

// mouse control
camera.wheelDeltaPercentage = 0.05;  // zoom speed
camera.panningSensibility = 50;
camera.angularSensibilityX = 1000;
camera.angularSensibilityY = 1000;
// CAMERA-------------------------------------------------------------


// LIGHT-------------------------------------------------------------
const light = new BABYLON.HemisphericLight(
  "light",
  new BABYLON.Vector3(0.5, 1, 0),
  scene
);

light.intensity = 1.4;

const light2 = new BABYLON.DirectionalLight(
  "light2",
  new BABYLON.Vector3(0.1, -1, 0.1),
  scene
);

light2.intensity = 3;
// LIGHT-------------------------------------------------------------


// MATERIAL-------------------------------------------------------------

const glow = new BABYLON.GlowLayer("glow", scene);
glow.intensity = 1.5;

const lightboxMat1 = new BABYLON.PBRMaterial("lightboxMat", scene);
lightboxMat1.emissiveColor = new BABYLON.Color3(1, 0.15, 0.2);
lightboxMat1.emissiveIntensity = 0.7;
lightboxMat1.albedoColor = new BABYLON.Color3(0.5, 0.2, 0.2);
lightboxMat1.metallic = 0;
lightboxMat1.roughness = 0;
lightboxMat1.disableLighting = true;

const lightboxMat2 = new BABYLON.PBRMaterial("lightboxMat", scene);
lightboxMat2.emissiveColor = new BABYLON.Color3(0.15, 0.2, 1);
lightboxMat2.emissiveIntensity = 0.7;
lightboxMat2.albedoColor = new BABYLON.Color3(0.2, 0.2, 0.5);
lightboxMat2.metallic = 0;
lightboxMat2.roughness = 0;
lightboxMat2.disableLighting = true;

const lightboxMat3 = new BABYLON.PBRMaterial("lightboxMat", scene);
lightboxMat3.emissiveColor = new BABYLON.Color3(0.6, 0.6, 0.6);
lightboxMat3.emissiveIntensity = 0.7;
lightboxMat3.albedoColor = new BABYLON.Color3(0.7, 0.7, 0.7);
lightboxMat3.metallic = 0;
lightboxMat3.roughness = 0;
lightboxMat3.disableLighting = true;

// MATERIAL-------------------------------------------------------------


// GEOMETRY-------------------------------------------------------------

// SPHERE-------------------------------------------------------------
const sphere = BABYLON.MeshBuilder.CreateSphere(
  "sphere",
  { diameter: ballSize },
  scene
);

sphere.position.x = game.ballPosX;
sphere.position.z = game.ballPosY;
sphere.position.y = 0.25;
sphere.material = lightboxMat3;

// SPHERE2-------------------------------------------------------------
const sphere2 = BABYLON.MeshBuilder.CreateSphere(
  "sphere2",
  { diameter: ballSize - 0.1},
  scene
);

// BOX-------------------------------------------------------------
const box = BABYLON.MeshBuilder.CreateBox(
  "box",
  { width: 0.2, height: 1, depth: padSize },
  scene
);
box.position.x = siteLength / 2.0 + 0.5 * ballSize;
box.position.y = 0.5;
box.position.z = game.leftRacketPos;
box.material = lightboxMat2;

// BOX2-------------------------------------------------------------
const box2 = BABYLON.MeshBuilder.CreateBox(
  "box2",
  { width: 0.2, height: 1, depth: padSize },
  scene
);
box2.position.x = - siteLength / 2.0 - 0.5 * ballSize;
box2.position.y = 0.5;
box2.position.z = game.rightRacketPos;
box2.material = lightboxMat1;
// BOX-------------------------------------------------------------
// GEOMETRY-------------------------------------------------------------


// LOAD_MODEL-------------------------------------------------------------
let currentMesh : any[]  = [];
function load_model(filename : string) : void
{
  currentMesh.forEach(mesh => mesh.dispose());
  currentMesh = [];

  BABYLON.SceneLoader.ImportMesh("", '/assets/model/', filename, scene, function(meshes: any)
  {
    console.log("info [client]: 3d model loaded successfully!");
    currentMesh = meshes;
  });
}
// LOAD_MODEL-------------------------------------------------------------

function run_babylon()
{
  resizeCanvasForHiDPI();

  engine.runRenderLoop(() => {
    try{
      box.position.z = game.rightRacketPos;
      box2.position.z = game.leftRacketPos;
      sphere.position.x = game.ballPosX;
      sphere.position.z = game.ballPosY;
    
      sphere2.position.x = p.x;
      sphere2.position.z = p.y;
      scene.render();
    }
    catch
    {
      ;
    }
  });
}

function stop_babylon()
{
  try{
    engine.stopRenderLoop();
  }
  catch(e)
  {
    ;
  }
}


