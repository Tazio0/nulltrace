import { useEffect, useRef } from "react";
import { geoEquirectangular, geoGraticule10, geoPath } from "d3-geo";
import * as THREE from "three";
import { feature, mesh } from "topojson-client";
import countries110m from "world-atlas/countries-110m.json";

const SCENE_TARGETS = {
  signal: { scale: 1.05, x: -0.2, y: 2.08, z: 0 },
  monitor: { scale: 0.92, x: -0.28, y: 2.32, z: 0 },
  feed: { scale: 0.82, x: -0.1, y: 2.82, z: 0 },
  discord: { scale: 0.78, x: 0.08, y: 3.14, z: 0 },
  exports: { scale: 0.74, x: 0.16, y: 3.55, z: 0 },
  system: { scale: 0.7, x: 0.22, y: 3.95, z: 0 }
};

export default function GlobeCanvas({ activeSection, routes }) {
  const mountRef = useRef(null);
  const activeRef = useRef(activeSection);

  useEffect(() => {
    activeRef.current = activeSection;
  }, [activeSection]);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return undefined;

    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const isSmallScreen = window.matchMedia("(max-width: 720px)").matches;
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 100);
    camera.position.set(0, 0, 6.55);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, isSmallScreen ? 1.4 : 2));
    mount.appendChild(renderer.domElement);

    const root = new THREE.Group();
    root.rotation.set(SCENE_TARGETS.signal.x, SCENE_TARGETS.signal.y, 0);
    root.scale.setScalar(SCENE_TARGETS.signal.scale);
    scene.add(root);

    const globeSegments = isSmallScreen ? 72 : 96;
    const wireSegments = isSmallScreen ? 56 : 72;
    const landTexture = createLandTexture(isSmallScreen ? 1024 : 2048);
    const land = new THREE.Mesh(
      new THREE.SphereGeometry(2.005, globeSegments, globeSegments),
      new THREE.MeshBasicMaterial({
        map: landTexture,
        transparent: true,
        opacity: 0.92,
        blending: THREE.AdditiveBlending,
        depthWrite: false
      })
    );
    root.add(land);

    const wire = new THREE.Mesh(
      new THREE.SphereGeometry(2.03, wireSegments, wireSegments),
      new THREE.MeshBasicMaterial({
        color: 0xf2f2f2,
        wireframe: true,
        transparent: true,
        opacity: 0.11,
        blending: THREE.AdditiveBlending
      })
    );
    root.add(wire);

    const pointCloud = createPointCloud(isSmallScreen ? 560 : 900);
    root.add(pointCloud);

    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(2.32, 72, 72),
      new THREE.MeshBasicMaterial({
        color: 0xf8f8f8,
        transparent: true,
        opacity: 0.055,
        side: THREE.BackSide,
        blending: THREE.AdditiveBlending
      })
    );
    root.add(atmosphere);

    const routeGroup = new THREE.Group();
    root.add(routeGroup);

    const animatedRoutes = routes.map((route, index) => {
      const curve = createRouteCurve(route);
      const lineGeometry = new THREE.BufferGeometry().setFromPoints(curve.getPoints(120));
      const lineMaterial = new THREE.LineDashedMaterial({
        color: route.color,
        transparent: true,
        opacity: route.severity === "critical" ? 0.8 : 0.48,
        dashSize: 0.055,
        gapSize: 0.055,
        blending: THREE.AdditiveBlending
      });
      const line = new THREE.Line(lineGeometry, lineMaterial);
      line.computeLineDistances();
      routeGroup.add(line);

      const particle = new THREE.Mesh(
        new THREE.SphereGeometry(route.severity === "critical" ? 0.044 : 0.034, 16, 16),
        new THREE.MeshBasicMaterial({ color: route.color, blending: THREE.AdditiveBlending })
      );
      routeGroup.add(particle);

      const origin = latLonToVector3(route.originLat, route.originLon, 2.055);
      const target = latLonToVector3(route.targetLat, route.targetLon, 2.065);
      routeGroup.add(createNode(origin, route.color, 0.035));
      routeGroup.add(createNode(target, route.color, route.targetCode === "ZA" ? 0.06 : 0.045));

      return {
        curve,
        lineMaterial,
        particle,
        particleTarget: new THREE.Vector3(),
        speed: route.speed,
        offset: route.offset + index * 0.031
      };
    });

    const zaHalo = createHalo(latLonToVector3(-30.5595, 22.9375, 2.08));
    routeGroup.add(zaHalo);

    const clock = new THREE.Clock();
    let rafId = 0;
    let disposed = false;

    const resize = () => {
      const width = Math.max(mount.clientWidth, 1);
      const height = Math.max(mount.clientHeight, 1);
      const aspect = width / height;
      const compact = width < 720 || aspect < 0.75;
      const fov = compact ? 54 : 42;
      const fitDiameter = 4.9;
      const fitDistance = Math.max(
        compact ? 7.2 : 6.55,
        fitDiameter / (2 * Math.tan(THREE.MathUtils.degToRad(fov / 2))),
        fitDiameter / (2 * Math.tan(THREE.MathUtils.degToRad(fov / 2)) * aspect)
      );

      camera.fov = fov;
      camera.position.z = fitDistance;
      renderer.setSize(width, height, false);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, compact ? 1.4 : 2));
      camera.aspect = aspect;
      camera.updateProjectionMatrix();
    };

    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(mount);
    resize();

    const renderFrame = () => {
      const elapsed = clock.getElapsedTime();
      const target = SCENE_TARGETS[activeRef.current] || SCENE_TARGETS.signal;
      const wobble = reducedMotion ? 0 : Math.sin(elapsed * 0.24) * 0.035;

      root.scale.setScalar(THREE.MathUtils.lerp(root.scale.x, target.scale, 0.035));
      root.rotation.x += (target.x + wobble * 0.32 - root.rotation.x) * 0.03;
      root.rotation.y += (target.y + wobble - root.rotation.y) * 0.024;
      root.rotation.z += (target.z - root.rotation.z) * 0.035;

      wire.rotation.y += reducedMotion ? 0 : 0.0009;
      pointCloud.rotation.y -= reducedMotion ? 0 : 0.00055;
      atmosphere.scale.setScalar(1 + (reducedMotion ? 0 : Math.sin(elapsed * 0.85) * 0.012));

      animatedRoutes.forEach((item, index) => {
        const t = reducedMotion ? item.offset % 1 : (elapsed * item.speed + item.offset) % 1;
        item.curve.getPointAt(t, item.particleTarget);
        item.particle.position.copy(item.particleTarget);
        item.lineMaterial.dashOffset = reducedMotion ? 0 : -elapsed * (0.018 + index * 0.002);
      });

      zaHalo.lookAt(camera.position);
      zaHalo.material.opacity = 0.23 + (reducedMotion ? 0 : Math.sin(elapsed * 1.4) * 0.08);

      renderer.render(scene, camera);

      if (!reducedMotion && !disposed) {
        rafId = requestAnimationFrame(renderFrame);
      }
    };

    renderFrame();

    return () => {
      disposed = true;
      cancelAnimationFrame(rafId);
      resizeObserver.disconnect();
      disposeObject(scene);
      renderer.dispose();
      landTexture.dispose();
      renderer.domElement.remove();
    };
  }, [routes]);

  return <div className="globe-canvas" ref={mountRef} aria-hidden="true" />;
}

function createRouteCurve(route) {
  const start = latLonToVector3(route.originLat, route.originLon, 2.08);
  const end = latLonToVector3(route.targetLat, route.targetLon, 2.08);
  const distance = start.distanceTo(end);
  const altitude = 2.28 + distance * 0.22;
  const mid = start.clone().add(end).normalize().multiplyScalar(altitude);
  return new THREE.QuadraticBezierCurve3(start, mid, end);
}

function latLonToVector3(lat, lon, radius) {
  const phi = THREE.MathUtils.degToRad(90 - lat);
  const theta = THREE.MathUtils.degToRad(lon + 180);
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta)
  );
}

function createNode(position, color, size) {
  const node = new THREE.Group();
  const core = new THREE.Mesh(
    new THREE.SphereGeometry(size, 16, 16),
    new THREE.MeshBasicMaterial({ color, blending: THREE.AdditiveBlending })
  );
  node.add(core);

  const ring = new THREE.Mesh(
    new THREE.TorusGeometry(size * 2.2, size * 0.16, 8, 28),
    new THREE.MeshBasicMaterial({
      color,
      transparent: true,
      opacity: 0.55,
      blending: THREE.AdditiveBlending
    })
  );
  ring.lookAt(position.clone().multiplyScalar(2));
  node.add(ring);
  node.position.copy(position);
  return node;
}

function createHalo(position) {
  const halo = new THREE.Mesh(
    new THREE.RingGeometry(0.17, 0.29, 48),
    new THREE.MeshBasicMaterial({
      color: 0xd8ff79,
      transparent: true,
      opacity: 0.22,
      side: THREE.DoubleSide,
      blending: THREE.AdditiveBlending
    })
  );
  halo.position.copy(position);
  return halo;
}

function createPointCloud(count = 900) {
  const positions = new Float32Array(count * 3);
  const radius = 2.075;
  const golden = Math.PI * (3 - Math.sqrt(5));

  for (let i = 0; i < count; i += 1) {
    const y = 1 - (i / (count - 1)) * 2;
    const r = Math.sqrt(1 - y * y);
    const theta = golden * i;
    positions[i * 3] = Math.cos(theta) * r * radius;
    positions[i * 3 + 1] = y * radius;
    positions[i * 3 + 2] = Math.sin(theta) * r * radius;
  }

  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  const material = new THREE.PointsMaterial({
    color: 0xffffff,
    size: 0.011,
    transparent: true,
    opacity: 0.28,
    blending: THREE.AdditiveBlending,
    depthWrite: false
  });

  return new THREE.Points(geometry, material);
}

function createLandTexture(width = 2048) {
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = width / 2;
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  const projection = geoEquirectangular()
    .translate([canvas.width / 2, canvas.height / 2])
    .scale(canvas.width / (2 * Math.PI));
  const path = geoPath(projection, ctx);
  const countries = feature(countries110m, countries110m.objects.countries);
  const borders = mesh(countries110m, countries110m.objects.countries, (a, b) => a !== b);
  const coastlines = mesh(countries110m, countries110m.objects.countries, (a, b) => a === b);
  const southAfrica = countries.features.find((country) => country.properties?.name === "South Africa");

  ctx.fillStyle = "rgba(235, 235, 235, 0.12)";
  ctx.beginPath();
  path(countries);
  ctx.fill();

  ctx.strokeStyle = "rgba(255, 255, 255, 0.16)";
  ctx.lineWidth = width >= 2048 ? 0.9 : 0.55;
  ctx.beginPath();
  path(geoGraticule10());
  ctx.stroke();

  ctx.strokeStyle = "rgba(255, 255, 255, 0.58)";
  ctx.lineWidth = width >= 2048 ? 1.7 : 1.05;
  ctx.beginPath();
  path(coastlines);
  ctx.stroke();

  ctx.strokeStyle = "rgba(205, 205, 205, 0.36)";
  ctx.lineWidth = width >= 2048 ? 0.72 : 0.48;
  ctx.beginPath();
  path(borders);
  ctx.stroke();

  if (southAfrica) {
    ctx.fillStyle = "rgba(255, 255, 255, 0.2)";
    ctx.strokeStyle = "rgba(255, 255, 255, 0.86)";
    ctx.lineWidth = width >= 2048 ? 2.4 : 1.45;
    ctx.beginPath();
    path(southAfrica);
    ctx.fill();
    ctx.stroke();
  }

  const texture = new THREE.CanvasTexture(canvas);
  texture.anisotropy = 8;
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function disposeObject(object) {
  object.traverse((child) => {
    if (child.geometry) child.geometry.dispose();
    if (child.material) {
      if (Array.isArray(child.material)) {
        child.material.forEach((material) => material.dispose());
      } else {
        child.material.dispose();
      }
    }
  });
}
