(() => {
  "use strict";

  const picker = document.querySelector("#control-center-account");
  if (picker) {
    picker.addEventListener("change", () => {
      const url = new URL(window.location.href);
      url.searchParams.set("account_id", picker.value);
      url.hash = "";
      window.location.assign(url.toString());
    });
  }
})();
