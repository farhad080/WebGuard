export function renderGreeting(el, user) {
  el.innerHTML = '<h1>Hello ' + user.name + '</h1>';
  el.title = 'greeting';
}
