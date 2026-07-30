(() => {
  "use strict";

  const picker = document.querySelector("#control-center-account");
  if (picker) {
    picker.addEventListener("change", () => {
      const url = new URL(window.location.href);
      url.searchParams.delete("account_id");
      url.searchParams.delete("account_public_id");
      url.searchParams.set("account", picker.value);
      url.hash = "";
      window.location.assign(url.toString());
    });
  }
})();
