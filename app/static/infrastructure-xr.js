const DEPTH = -2.6;
const VERTEX = `
  attribute vec3 position;
  attribute vec2 uv;
  uniform mat4 projection;
  uniform mat4 view;
  varying vec2 coordinate;
  void main() {
    gl_Position = projection * view * vec4(position, 1.0);
    coordinate = uv;
  }`;
const FRAGMENT = `
  precision mediump float;
  varying vec2 coordinate;
  uniform sampler2D mapTexture;
  void main() { gl_FragColor = texture2D(mapTexture, coordinate); }
`;
const COLORS = {ok: '#13744d', warn: '#9a6300', critical: '#b53140', unknown: '#687789'};

function shader(gl, type, source) {
  const result = gl.createShader(type);
  gl.shaderSource(result, source);
  gl.compileShader(result);
  if (!gl.getShaderParameter(result, gl.COMPILE_STATUS)) throw new Error('WebGL shader compilation failed');
  return result;
}

function paint(canvas, layout, selected) {
  const padding = 24;
  const footer = 50;
  const boardWidth = layout.width + padding * 2;
  const boardHeight = layout.height + padding * 2 + footer;
  const scale = Math.min(2, 2048 / Math.max(boardWidth, boardHeight));
  canvas.width = Math.ceil(boardWidth * scale);
  canvas.height = Math.ceil(boardHeight * scale);
  const ctx = canvas.getContext('2d');
  ctx.scale(scale, scale);
  ctx.fillStyle = '#fbfcfe';
  ctx.fillRect(0, 0, boardWidth, boardHeight);
  ctx.translate(padding, padding);
  ctx.textBaseline = 'middle';
  for (const line of layout.lines) {
    ctx.save();
    ctx.translate(line.x, line.y);
    ctx.strokeStyle = line.active ? '#2859a5' : '#8c9caf';
    ctx.lineWidth = line.active ? 2 : 1;
    ctx.stroke(new Path2D(line.path));
    ctx.restore();
  }
  for (const heading of layout.headings) {
    ctx.font = '600 15px system-ui';
    ctx.fillStyle = '#152132';
    ctx.fillText(heading.text, heading.x, heading.y + heading.height / 2);
  }
  for (const node of layout.nodes) {
    ctx.beginPath();
    ctx.roundRect(node.x, node.y, node.width, node.height, 6);
    ctx.fillStyle = node.id === selected ? '#e0ebfa' : '#f3f6f9';
    ctx.fill();
    ctx.strokeStyle = node.id === selected ? '#2859a5' : '#a5b2c0';
    ctx.stroke();
    ctx.beginPath();
    ctx.fillStyle = COLORS[node.status];
    ctx.arc(node.x + 10, node.y + node.height / 2, 3.5, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = '#152132';
    ctx.font = '600 12px system-ui';
    ctx.fillText(node.text, node.x + 19, node.y + node.height / 2, Math.max(10, node.width - 24));
  }
  const chosen = layout.nodes.find(node => node.id === selected);
  if (chosen) {
    ctx.font = '600 17px system-ui';
    ctx.fillStyle = COLORS[chosen.status];
    ctx.fillText(chosen.name + ' · ' + chosen.state, 0, layout.height + footer / 2, layout.width);
  }
  return {boardWidth, boardHeight, padding};
}

export async function setupInfrastructureVr(button, status, getLayout) {
  const xr = navigator.xr;
  if (!window.isSecureContext || !xr || !window.XRWebGLLayer) return;
  try {
    if (!await xr.isSessionSupported('immersive-vr')) return;
  } catch {
    return;
  }
  button.hidden = false;
  button.addEventListener('click', async () => {
    button.disabled = true;
    status.hidden = true;
    let session;
    const surface = document.createElement('canvas');
    const gl = surface.getContext('webgl', {alpha: false});
    try {
      if (!gl) throw new Error('WebGL unavailable');
      const layout = getLayout();
      if (!layout.nodes.length || layout.width <= 0 || layout.height <= 0) throw new Error('Empty topology');
      session = await xr.requestSession('immersive-vr');
      session.addEventListener('end', () => { button.disabled = false; }, {once: true});
      await gl.makeXRCompatible();
      const layer = new window.XRWebGLLayer(session, gl);
      session.updateRenderState({baseLayer: layer});
      const reference = await session.requestReferenceSpace('local');
      drawSession(session, gl, layer, reference, layout);
    } catch {
      if (session) await session.end().catch(() => {});
      button.disabled = false;
      status.textContent = 'Не удалось открыть карту в VR.';
      status.hidden = false;
    }
  });
}

function drawSession(session, gl, layer, reference, layout) {
  const board = document.createElement('canvas');
  const program = gl.createProgram();
  const vertex = shader(gl, gl.VERTEX_SHADER, VERTEX);
  const fragment = shader(gl, gl.FRAGMENT_SHADER, FRAGMENT);
  gl.attachShader(program, vertex);
  gl.attachShader(program, fragment);
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error('WebGL program link failed');
  gl.useProgram(program);
  gl.deleteShader(vertex);
  gl.deleteShader(fragment);
  const dimensions = paint(board, layout, layout.selected);
  const ratio = dimensions.boardWidth / dimensions.boardHeight;
  const halfWidth = Math.min(1.48, 0.95 * ratio);
  const halfHeight = halfWidth / ratio;
  const buffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([
    -halfWidth, -halfHeight, DEPTH, 0, 1,
     halfWidth, -halfHeight, DEPTH, 1, 1,
    -halfWidth,  halfHeight, DEPTH, 0, 0,
     halfWidth,  halfHeight, DEPTH, 1, 0,
  ]), gl.STATIC_DRAW);
  for (const [name, size, offset] of [['position', 3, 0], ['uv', 2, 12]]) {
    const attribute = gl.getAttribLocation(program, name);
    gl.enableVertexAttribArray(attribute);
    gl.vertexAttribPointer(attribute, size, gl.FLOAT, false, 20, offset);
  }
  const projection = gl.getUniformLocation(program, 'projection');
  const view = gl.getUniformLocation(program, 'view');
  const texture = gl.createTexture();
  gl.bindTexture(gl.TEXTURE_2D, texture);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
  const upload = () => gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, board);
  upload();

  session.addEventListener('select', event => {
    const pose = event.frame.getPose(event.inputSource.targetRaySpace, reference);
    if (!pose) return;
    const matrix = pose.transform.matrix;
    const direction = -matrix[10];
    if (Math.abs(direction) < 0.0001) return;
    const distance = (DEPTH - matrix[14]) / direction;
    if (distance <= 0) return;
    const x = (0.5 + (matrix[12] - matrix[8] * distance) / (2 * halfWidth)) * dimensions.boardWidth - dimensions.padding;
    const y = (0.5 - (matrix[13] - matrix[9] * distance) / (2 * halfHeight)) * dimensions.boardHeight - dimensions.padding;
    const chosen = layout.nodes.find(node => x >= node.x && x <= node.x + node.width && y >= node.y && y <= node.y + node.height);
    if (!chosen) return;
    paint(board, layout, chosen.id);
    upload();
  });
  let frameId;
  const renderFrame = (_, frame) => {
    frameId = session.requestAnimationFrame(renderFrame);
    const pose = frame.getViewerPose(reference);
    if (!pose) return;
    gl.bindFramebuffer(gl.FRAMEBUFFER, layer.framebuffer);
    gl.clearColor(0.07, 0.10, 0.15, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    for (const eye of pose.views) {
      const viewport = layer.getViewport(eye);
      if (!viewport) continue;
      gl.viewport(viewport.x, viewport.y, viewport.width, viewport.height);
      gl.uniformMatrix4fv(projection, false, eye.projectionMatrix);
      gl.uniformMatrix4fv(view, false, eye.transform.inverse.matrix);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    }
  };
  frameId = session.requestAnimationFrame(renderFrame);
  session.addEventListener('end', () => {
    session.cancelAnimationFrame(frameId);
    gl.deleteTexture(texture);
    gl.deleteBuffer(buffer);
    gl.deleteProgram(program);
  }, {once: true});
}
