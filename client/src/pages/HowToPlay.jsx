import Page from "../components/Page.jsx";

export default function HowToPlay() {
  return (
    <Page title="How to Play" back="/">
      <ol>
        <li>One person creates a group and shares the invite link.</li>
        <li>Everyone joins and claims their name.</li>
        <li>The admin draws names. Each person becomes a secret Chris-Mom to exactly one Chris-Child.</li>
        <li>Open your chit to find your Chris-Child, and keep it secret.</li>
        <li>Give small gifts and kind surprises, then reveal yourself at the end.</li>
      </ol>
      <h2>About</h2>
      <p>
        Chris-Mom &amp; Chris-Child is a family game: nobody draws themselves, and everyone
        has exactly one Chris-Mom.
      </p>
    </Page>
  );
}
