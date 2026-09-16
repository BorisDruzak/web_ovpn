document.addEventListener("change", (event) => {
  const target = event.target;
  if (target.matches("input[type='file']") && target.files.length) {
    target.setAttribute("data-selected", "true");
  }
});
